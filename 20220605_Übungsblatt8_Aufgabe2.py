# Julian Lemmerich
# DHBW Mannheim Kryptologie
# Übungsblatt 8 Aufgabe 2

import sys

def diffie_hellman(a: int, b: int, g: int, p: int, verbose=False) -> int:
    """caluclates the shared secret key of a and b using the Diffie-Hellman algorithm
    
    Arguments:
        a {int} -- the private key of Alice
        b {int} -- the private key of Bob
        g {int} -- the generator of the cyclic group
        p {int} -- the modulus of the cyclic group
        
    Keyword Arguments:
        verbose {bool} -- whether to print the intermediate values (default: {False})
    
    Returns:
        int -- the shared secret key"""
    alpha = pow(g, a, p)
    if verbose: print(f"pubkey Alice: {alpha}")
    beta = pow(g, b, p)
    if verbose: print(f"pubkey Bob: {beta}")
    k1 = pow(alpha, b, p)
    k2 = pow(beta, a, p)
    assert k1 == k2
    k = k1
    if verbose: print(f"shared key: {k}")
    return k

def task82():
    print("# Task 8.2)\n")
    p = 467
    g = 2
    print("\n## Task 8.2.1)\n")
    diffie_hellman(a=3, b=5, g=g, p=p, verbose=True)
    print("\n## Task 8.2.2)\n")
    diffie_hellman(a=400, b=134, g=g, p=p, verbose=True)
    print("\n## Task 8.2.3)\n")
    diffie_hellman(a=228, b=57, g=g, p=p, verbose=True)

def test():
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2: task82()
    elif sys.argv[1] == 'test': test()