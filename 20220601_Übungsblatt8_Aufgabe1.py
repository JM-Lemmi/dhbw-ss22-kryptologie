# Julian Lemmerich
# DHBW Mannheim Kryptologie
# Übungsblatt 8 Aufgabe 1

import math
import sys

def el_cyclicgroup(n: int) -> list:
    """returns a list of all elements in the cyclic group of order n"""
    return [el for el in range(1, n) if math.gcd(el, n) == 1]

def ord(a: int, n: int) -> int:
    """returns the order of element a in the cyclic group of order n"""
    for k in range(1, n):
        if (a**k) % n == 1:
            return k

def is_primitive_el(a: int, n: int) -> bool:
    """returns true if a is a primitive element of the cyclic group of order n"""
    return ord(a, n) == len(el_cyclicgroup(n))

def task81():
    print("# Task 8.1)\n")
    print("## Task 8.1a)\n")
    print(f"Die multiplikative Gruppe \\mathbb{{Z}}_{{17}}^* hat {len(el_cyclicgroup(17))} Elemente.\n")
    print("## Task 8.1b)\n")
    print(f"|{'a':^4}|{'Ord':^5}|\n|----|-----|")
    for a in el_cyclicgroup(17):
        print(f"|{a:^4}|{ord(a, 17):^5}|")
    print("\n## Task 8.1c)\n")
    print(f"|{'b':^4}|{'primitiv?':^10}|\n|----|----------|")
    for b in el_cyclicgroup(17):
        print(f"|{b:^4}|{is_primitive_el(b, 17)!s:^10}|")

def test():
    assert el_cyclicgroup(5) == [1, 2, 3, 4]
    assert ord(3, 11) == 5
    print("Tests successful!")

if __name__ == "__main__":
    if len(sys.argv) < 2: task81()
    elif sys.argv[1] == 'test': test()