import math

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