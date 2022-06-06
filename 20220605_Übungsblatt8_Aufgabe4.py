# Julian Lemmerich
# DHBW Mannheim, Kryptologe
# Übungsblatt 8, Aufgabe 4

import string
import sys
import hashlib

def bytes_from_int(i: int, l: int=None) -> bytes:
    """
    Convert an integer to a byte string.

    Fixes overflow issues with builtin function bytes().
    """
    a = hex(i)[2:]
    if len(a) % 2 == 1:
        a = "0" + a
    if l is not None:
        while len(a) < l:
            a = "00" + a
    b = bytes.fromhex(a)
    return b

def task84():
    p = 2 ** 206 - 5
    q = 2 ** 226 - 5
    n = p * q
    d = int("affe0815", 16)
    print("\n# Task 8.4)\n")

    print("\n## Task 8.4.1)\n")
    print(decrypt_task84("78766a52455329b486aaa414c3a029834a7e4b6ed87019dce4056f4d8999b137404d9ec4df28da201c9b0bc142deb1d86ff94d83becc", d, n))

    print("\n## Task 8.4.2)\n")
    print(decrypt_task84("670b865216dfd0aacd5f7fa8802e704fa82f3fb9c7dbe3eb5a9ec308a1a2288648b15d5cc8ba2f54b245a972aea977932c9c84cf6422", d, n))

    print("\n## Task 8.4.3)\n")
    print(decrypt_task84("61d5f2a4298bff3d6ebcd78830fb9181d97235623819eb7c60b92dcdf836a6cf731c60187e72f471c05d1c6eab216c3f6032af3c5370", d, n))

    print("\n## Task 8.4.4)\n")
    print(decrypt_task84("3651009d02a0c72b9bc206c57d12277594d9eaad28bb3de5d661670b42f1cfafe688b9674e34d4ad79db898205417086e7e1877b9ef1", d, n))

    print("\n## Task 8.4.5)\n")
    print(decrypt_task84("96e51d4675c6be5b14ec0cf2a9e9a9610a99d632723b3f1fcfc6b36806f5d74045f47622817cc35f6ffe9afe29f0aa236cbe12371651", d, n))

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

def decrypt_task84(c, d, n):
    """
    Decrypt a message with RSA, with the correct leading zeroes.

    Arguments:
        c {string} -- ciphertext to be decrypted
        d {int} -- private key for decryption
        n {int} -- modulus
    
    Returns:
        string -- decrypted message
    """
    i = int(c, 16)
    x_int = rsa(i, d, n)
    x = bytes_from_int(x_int, len(c)) #die länge hier ist nötig für die leading zeroes
    return x.hex()

if __name__ == "__main__":
    if len(sys.argv) < 2: task84()
    #elif sys.argv[1] == 'test': test()