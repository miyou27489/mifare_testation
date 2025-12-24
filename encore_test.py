from pathlib import Path
import struct
from itertools import product

SENTINEL = bytes.fromhex("58 9f 43 46 87 07 7b b2")
PurseBlocks = [36, 37, 40, 41, 42, 45]  # constaté sur tes dumps

def load_blocks(path: str) -> list[bytes]:
    data = Path(path).read_bytes()
    if len(data) != 1024:
        raise ValueError(f"Expected 1024 bytes, got {len(data)}")
    return [data[i:i+16] for i in range(0, 1024, 16)]

def extract_payload8(block: bytes) -> bytes | None:
    # sentinelle en tête -> payload sur les 8 derniers octets
    if block[:8] == SENTINEL:
        return block[8:16]
    # sentinelle en queue -> payload sur les 8 premiers octets
    if block[8:16] == SENTINEL:
        return block[0:8]
    return None

def dump_payloads(path: str) -> dict[int, bytes]:
    blocks = load_blocks(path)
    out = {}
    for b in PurseBlocks:
        p = extract_payload8(blocks[b])
        if p is not None:
            out[b] = p
    return out

def hexd(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

# --- Détecteur "CM2": cherche un champ qui suit parfaitement les valeurs en centimes
# Supporte : direct / NOT / XOR constant (8,16,32-bit) / +const (mod 2^n)
def candidates_for(values: list[int], blobs: list[bytes], bits: int):
    mask = (1 << bits) - 1

    def read_int(b: bytes, off: int, endian: str):
        if bits == 8:
            return b[off]
        if bits == 16:
            fmt = "<H" if endian == "le" else ">H"
            return struct.unpack_from(fmt, b, off)[0]
        if bits == 32:
            fmt = "<I" if endian == "le" else ">I"
            return struct.unpack_from(fmt, b, off)[0]
        raise ValueError(bits)

    endians = ["le", "be"] if bits in (16, 32) else ["le"]
    max_off = 8 - (bits // 8)
    for off in range(0, max_off + 1):
        for endian in endians:
            raw = [read_int(bb, off, endian) for bb in blobs]

            # 1) direct match
            if raw == values:
                yield ("direct", bits, endian, off, None)

            # 2) NOT
            inv = [(~x) & mask for x in raw]
            if inv == values:
                yield ("not", bits, endian, off, None)

            # 3) XOR constant: k = raw ^ val must be constant for all samples
            k = raw[0] ^ values[0]
            if all((r ^ k) == v for r, v in zip(raw, values)):
                yield ("xor", bits, endian, off, k)

            # 4) + constant mod 2^n : (raw + k) % 2^n == val
            k = (values[0] - raw[0]) & mask
            if all(((r + k) & mask) == v for r, v in zip(raw, values)):
                yield ("add", bits, endian, off, k)

def find_simple_decoder(samples: list[tuple[str, float]]):
    # samples: [("dump_1.mfd", 1.08), ("dump_2.mfd", 1.18), ...]
    # Convertit en centimes entiers
    vals = [int(round(v * 100)) for _, v in samples]

    # Construit un tableau: pour chaque bloc purse, on a une suite de payload8
    payload_by_block = {b: [] for b in PurseBlocks}
    for path, _ in samples:
        payloads = dump_payloads(path)
        for b in PurseBlocks:
            payload_by_block[b].append(payloads.get(b, b""))

    print("== Payloads repérés ==")
    for b in PurseBlocks:
        ok = all(len(x) == 8 for x in payload_by_block[b])
        print(f"Block {b:02d}: {'OK' if ok else 'NO-SENTINEL'}")

    print("\n== Recherche d'encodage simple (centimes) ==")
    found = []
    for b in PurseBlocks:
        blobs = payload_by_block[b]
        if not blobs or any(len(x) != 8 for x in blobs):
            continue

        for bits in (8, 16, 32):
            for cand in candidates_for(vals, blobs, bits):
                found.append((b, *cand))

    if not found:
        print("Rien trouvé en direct/NOT/XOR/+const sur 8/16/32 bits dans les payload8.")
        print("=> il faut soit plus de points, soit c'est une combine un poil moins triviale (ex: split, checksum, mix entre blocs).")
        return

    print("MATCHES:")
    for (b, kind, bits, endian, off, k) in found:
        kstr = f" k=0x{k:0{bits//4}x}" if k is not None else ""
        print(f"- Block {b:02d} | {kind.upper()} | {bits}-bit {endian} off={off}{kstr}")

if __name__ == "__main__":
    samples = [
        ("dump_fifth.mfd",  1.08),
        ("dump_seventh.mfd", 1.18),
        # Ajoute 2 dumps de plus ici, mêmes règles
        # ("dump_x.mfd", 1.00),
        # ("dump_y.mfd", 1.01),
    ]
    find_simple_decoder(samples)
