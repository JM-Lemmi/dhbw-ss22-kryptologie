# Julian Lemmerich
# DHBW Mannheim, Kryptologie, Sommersemester 22

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
