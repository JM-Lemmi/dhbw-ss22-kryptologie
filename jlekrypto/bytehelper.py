# Julian Lemmerich
# DHBW Mannheim, Kryptologie, Sommersemester 22
# Hilfsfunktionen für Bytes

def bytes_xor(a: bytes, b: bytes) -> bytes:
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

def bytes_from_int(i: int, len: int=None) -> bytes:
    """
    Convert an integer to a byte string.

    Fixes overflow issues with builtin function bytes().
    """
    a = hex(i)[2:]
    if len(a) % 2 == 1:
        a = "0" + a
    if len is not None:
        while len(a) < len:
            a = "00" + a
    b = bytes.fromhex(a)
    return b