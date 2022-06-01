# Julian Lemmerich
# Kryptologie, DHBW Mannheim
# Übungsblatt 6, Aufgabe 4

import sys

def reduce_poly(inpoly: int, modpoly: int) -> int:
    while inpoly > modpoly & inpoly.bit_length() >= modpoly.bit_length():
        inpoly -= modpoly << (inpoly.bit_length() - modpoly.bit_length())
    return inpoly

def test():
    assert reduce_poly(0x1053, 0x100001) == 0x1053
    print("Test successful")

if __name__ == '__main__':
    if len(sys.argv) < 2: print("Usage:\n'test' for executing the test from the task.\n'calc <poly> <modpoly>' for calculating the inverse of <poly> modulo <modpoly>. poly and modpoly need to be in integer hexadecimal representation.\nThis program does not do any user entry checking. Please be aware of that!")
    elif sys.argv[1] == 'test': test()
    elif sys.argv[1] == 'calc': print(hex(reduce_poly(int(sys.argv[2], 16), int(sys.argv[3], 16))))
    else: print("Unknown argument")
