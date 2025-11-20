def dword(buffer, idx: int) -> int:
    return int.from_bytes(buffer[idx : idx + 4], "little")


def bytes_sub(buffer, start: int, length: int) -> bytes:
    return buffer[start : start + length]
