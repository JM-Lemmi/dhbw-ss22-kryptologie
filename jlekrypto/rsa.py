# Julian Lemmerich
# DHBW Mannheim, Kryptologie, Sommersemester 22

def rsa(m: int, e: int, n: int) -> int:
    """
    RSA encryption

    Arguments:
        m {int} -- message to be encrypted
        e {int} -- public exponent or private key for decryption
        n {int} -- modulus
    
    Returns:
        int -- encrypted message
    """
    return pow(m, e, n)