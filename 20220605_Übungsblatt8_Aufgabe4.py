# Julian Lemmerich
# DHBW Mannheim, Kryptologe
# Übungsblatt 8, Aufgabe 4

import sys
import hashlib

def bytes_from_int(i: int) -> bytes:
    """
    Convert an integer to a byte string.

    Fixes overflow issues with builtin function bytes().
    """
    a = hex(i)[2:]
    if len(a) % 2 == 1:
        a = "0" + a
    b = bytes.fromhex(a)
    return b

# from https://en.wikipedia.org/wiki/Mask_generation_function#Example_code, danke Frederik ;)
def mgf1(seed: bytes, length: int, hash_func=hashlib.sha1) -> bytes:
    hLen = hash_func().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1.If l > 2^32(hLen), output "mask too long" and stop.
    if length > (hLen << 32):
        raise ValueError("mask too long")
    # 2.Let T  be the empty octet string.
    T = b""
    # 3.For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
    # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
    #       but it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < length:
        # a.Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, 'big')
        # b.Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_func(seed + C).digest()
        counter += 1
    # 4.Output the leading l octets of T as the octet string mask.
    return T[:length]

def task84():
    p = 2 ** 206 - 5
    q = 2 ** 226 - 5
    n = p * q
    d = int("affe0815", 16)
    print("\n# Task 8.4)\n")

    print("\n## Task 8.4.1)\n")
    eins = bytes.fromhex("78766a52455329b486aaa414c3a029834a7e4b6ed87019dce4056f4d8999b137404d9ec4df28da201c9b0bc142deb1d86ff94d83becc")
    try:
        print(f"{rev_oaep(hashlib.sha1, eins, d, n, debug=True)=}")
    except Exception as e:
        print(e)

    print("\n## Task 8.4.2)\n")
    zwei = bytes.fromhex("670b865216dfd0aacd5f7fa8802e704fa82f3fb9c7dbe3eb5a9ec308a1a2288648b15d5cc8ba2f54b245a972aea977932c9c84cf6422")
    try:
        print(f"{rev_oaep(hashlib.sha1, zwei, d, n, debug=True)=}")
    except Exception as e:
        print(e)

    print("\n## Task 8.4.3)\n")
    drei = bytes.fromhex("61d5f2a4298bff3d6ebcd78830fb9181d97235623819eb7c60b92dcdf836a6cf731c60187e72f471c05d1c6eab216c3f6032af3c5370")
    try:
        print(f"{rev_oaep(hashlib.sha1, drei, d, n, debug=True)=}")
    except Exception as e:
        print(e)

    print("\n## Task 8.4.4)\n")
    vier = bytes.fromhex("3651009d02a0c72b9bc206c57d12277594d9eaad28bb3de5d661670b42f1cfafe688b9674e34d4ad79db898205417086e7e1877b9ef1")
    try:
        print(f"{rev_oaep(hashlib.sha1, vier, d, n, debug=True)=}")
    except Exception as e:
        print(e)

    print("\n## Task 8.4.5)\n")
    funf = bytes.fromhex("96e51d4675c6be5b14ec0cf2a9e9a9610a99d632723b3f1fcfc6b36806f5d74045f47622817cc35f6ffe9afe29f0aa236cbe12371651")
    try:
        print(f"{rev_oaep(hashlib.sha1, funf, d, n, debug=True)=}")
    except Exception as e:
        print(e)

def rev_oaep(mgf_hashfunc, cm: bytes, d: int, n: int, debug=False) -> bytes:
    """Decrypting OAEP

    Throws an error if the padding is not done correctly.

    Arguments:
        mgf_hashfunc {hashlib.func} -- mask generation function
        cm {bytes} -- encrypted message
        d {int} -- private key
        n {int} -- modulus
        debug {bool} -- print debug messages
    
    Returns:
        bytes -- decrypted message
    """

    # Decrypt message with rsa
    em_int = rsa(int.from_bytes(cm, byteorder="big"), d, n)
    em = bytes_from_int(em_int)
    if debug: print(f"{em.hex()=}, {len(em)=}")

    # Check if first byte of em is 0x00
    if em[:1] != 0: raise ValueError("First byte of em is not 0x00")
    # Split the message into seed and db
    maskedseedlen = mgf_hashfunc().digest_size
    maskedseed = em[1:1+maskedseedlen]
    maskeddb = em[1+maskedseedlen:]
    if debug: print(f"{maskedseed.hex()=}, {maskeddb.hex()=}")
    # generate the seed from the masked seed and masked DB
    seed = mgf1(maskeddb, maskedseedlen, mgf_hashfunc) ^ maskedseed
    if debug: print(f"{seed.hex()=}")
    # generate the DB from the seed and masked DB
    db = mgf1(seed, len(maskeddb), mgf_hashfunc) ^ maskeddb
    if debug: print(f"{db.hex()=}")

    # split db into its components
    #hash
    hlen = mgf_hashfunc().digest_size
    lhash = db[:hlen]
    #padding
    i = hlen
    while db[i:i+1] == 0: i += 1
    pslen = i - hlen
    if db[pslen+1] != 1: raise ValueError("DB is not padded correctly")
    #message
    m = db[pslen+2:]

    # check if hash of message is correct
    if lhash != mgf_hashfunc(m).digest(): raise ValueError("Hash of message is not correct")
    return m

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

if __name__ == "__main__":
    if len(sys.argv) < 2: task84()
    #elif sys.argv[1] == 'test': test()