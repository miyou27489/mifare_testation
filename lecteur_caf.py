from pathlib import Path

SENTINEL = bytes.fromhex("58 9f 43 46 87 07 7b b2")
CHANGED_BLOCKS = [36, 37, 40, 41, 42, 45]  # constaté sur tes 2 dumps

def load_blocks(path: str) -> list[bytes]:
    data = Path(path).read_bytes()
    if len(data) != 1024:
        raise ValueError(f"Expected 1024 bytes (Mifare Classic 1K), got {len(data)}")
    return [data[i:i+16] for i in range(0, 1024, 16)]

def classify_record(block: bytes) -> tuple[str, bytes]:
    """
    Retourne (position_sentinelle, payload_8_octets)
    - 'head' : sentinelle en début, payload = fin (8 bytes)
    - 'tail' : sentinelle en fin,  payload = début (8 bytes)
    - 'none' : pas de sentinelle, payload vide
    """
    if block[:8] == SENTINEL:
        return ("head", block[8:16])
    if block[8:16] == SENTINEL:
        return ("tail", block[0:8])
    return ("none", b"")

def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

def read_logic(dump_path: str) -> None:
    blocks = load_blocks(dump_path)

    print(f"== {dump_path} ==")
    records = []
    for idx in CHANGED_BLOCKS:
        pos, payload = classify_record(blocks[idx])
        records.append((idx, pos, payload, blocks[idx]))
    
    # Affichage brut + extraction payload
    for idx, pos, payload, raw in records:
        print(f"Block {idx:02d}  sentinel={pos:>4}  payload8={hexdump(payload)}  raw={hexdump(raw)}")

    # Petit check de cohérence: combien de blocs portent la sentinelle
    with_sentinel = [r for r in records if r[1] != "none"]
    print(f"\nSentinel found in {len(with_sentinel)}/{len(records)} blocks.")
    if len(with_sentinel) < 4:
        print("Warning: structure inattendue (trop peu de sentinelles).")

if __name__ == "__main__":
    read_logic("dump_fifth.mfd")
    read_logic("dump_seventh.mfd")
