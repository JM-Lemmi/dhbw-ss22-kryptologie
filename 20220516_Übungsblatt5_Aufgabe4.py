# Julian Lemmerich
# DHBW Mannheim, Kryptologie
# Übungsblatt 5, Aufgabe 4

import sys

def feistel(halfblock: int, key: int, verbose=False) -> int:
    log = print if verbose else lambda *args, **kwargs: None

    sbox = [0x4, 0x3, 0x9, 0xa, 0xb, 0x2, 0xe, 0x1, 0xd, 0xc, 0x8, 0x6, 0x7, 0x5, 0x0, 0xf]
    log(f"\t\tFeistel function: {hex(halfblock)=} with {hex(key)=}")
    newblock = reversenibble((halfblock >> 12) & 0xf) | reversenibble(halfblock & 0xf) << 12
    log(f"\t\tPermutated block: {hex(newblock)=}")
    newblock |= sbox[(halfblock >> 8) & 0xf] << 8
    newblock |= sbox[(halfblock >> 4) & 0xf] << 4
    log(f"\t\tS-boxed block: {hex(newblock)=}")
    res = newblock ^ key
    log(f"\t\tXORd block: {hex(res)=}")
    return res

def reversenibble(nibble: int) -> int:
    return (nibble & 0x8) >> 3 | (nibble & 0x4) >> 1 | (nibble & 0x2) << 1 | (nibble & 0x1) << 3

def round(block: int, key: int, verbose=False) -> int:
    log = print if verbose else lambda *args, **kwargs: None

    log(f"\tEncrypting {hex(block)=} with {hex(key)=}")
    lower_block = block & 0xffff
    upper_block = block >> 16
    log(f"\tLower block: {hex(lower_block)=}")
    log(f"\tUpper block: {hex(upper_block)=}")
    xor_key = feistel(lower_block, key, verbose)
    log(f"\tXOR key: {hex(xor_key)=}")
    res = (xor_key ^ upper_block) + (lower_block << 16)
    log(f"\tResult: {hex(res)=}")
    return res

def encrypt(block: int, ksa: list, verbose=False) -> int:
    for key in ksa:
        block = round(block, key, verbose)
    return block

def decrypt(block: int, ksa: list, verbose=False) -> int:
    #swap upper and lower block
    block = (block << 16) & 0xffff0000 | (block >> 16) & 0x0000ffff
    block = encrypt(block, reversed(ksa), verbose)
    #swap back
    block = (block >> 16) & 0x0000ffff | (block << 16) & 0xffff0000
    return block

def test():
    #from https://moodle.dhbw-mannheim.de/mod/forum/discuss.php?d=37396
    assert feistel(0x1234, 0x2345, True) == 0x0aed
    assert feistel(0xabcd, 0xbeef, True) == 0x089a
    assert feistel(0x9876, 0xfedc, True) == 0x93c5
    assert encrypt(0x12345678, [0x1aa2, 0x2bb3, 0x3cc4], True) == 0x4313e07a
    assert decrypt(0x4313e07a, [0x1aa2, 0x2bb3, 0x3cc4], True) == 0x12345678
    print("Test passed")

def main():
    print("Aufgabe 5.4")
    ksa = [0xdead, 0xc0ff, 0xee5a]
    print("1) Verschlüsseln von `0xabcd0815`:")
    eins = encrypt(0xabcd0815, ksa, False)
    print(f"{hex(eins)}")

    print("2) Entschlüsseln von `0x12345678`:")
    zwei = decrypt(0x12345678, ksa, False)
    print(f"{hex(zwei)}")

if __name__ == '__main__':
    if len(sys.argv) == 1: main()
    elif sys.argv[1] == 'test': test()
    else: print("Unknown argument")