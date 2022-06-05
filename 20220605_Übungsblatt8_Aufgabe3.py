# Julian Lemmerich
# DHBw Mannheim Kryptologie
# Übungsblatt 8 Aufgabe 3

import sys
import hashlib
import os

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

def oaep(mgf_hashfunc: hashlib.func, m: bytes, n: int, seedlen: int) -> bytes:
    """" OAEP Encoding

    Implementation without authenticated data L. (!, not compliant with RFC8017)
    seedlength is the length of the seed used in the mask generation function. Should be mgf_hashfunc.digest_size

    Arguments:
        mgf {hashlib.func} -- mask generation function
        m {bytes} -- message to be encoded
        n {int} -- modulus
        seedlen {int} -- length of the seed for mgf
    """

    # 2. Generate a pading string
    k = len(bytes(n))
    mlen = len(m)
    pslen = k - mlen - 2
    ps = b'\x00' * pslen
    # 3. Concatenate the the padding string, 0x01 and the message
    db = ps + b'\x01' + m
    # 4. Generate a random seed of length from seedlen (should be mgf_hashfunc.digest_size)
    hlen = mgf_hashfunc.digest_size
    seed = os.urandom(seedlen)
    # 5. Generate a mask of length of db using the MGF1 function
    dbmask = mgf_hashfunc(seed=seed, lenght=len(db), hash_func=mgf_hashfunc)
    # 6. Apply the mask to the datablock
    maskeddb = db ^ dbmask
    # 7. Generate a mask of length hlen for the seed
    seedmask = mgf_hashfunc(seed=maskeddb, lenght=hlen, hash_func=mgf_hashfunc)
    # 8. Apply the mask to the seed
    maskedseed = seed ^ seedmask
    # 9. concatenate the masked seed and the masked db for encoded message
    em = b'\x00' + maskedseed + maskeddb
    return em


def task83():
    print("# Task 8.3)\n")
    # n & e have to be manually extracted from the pubkey with openssl:
    # openssl rsa -pubin -in "20220605_Übungsblatt8_pubkey.pub" -text -noout
    # openssl rsa -pubin -in "20220605_Übungsblatt8_pubkey.pub" -modulus -noout
    e = 65537
    n = int("AF5466C26A6B662AC98C06023501C9DF6036B065BD1F6804B1FC86307718DA4048211FD68A06917DE6F81DC018DCAF84B38AB77A6538BA2FE6664D3FB81E4A0886BBCDAB071AD6823FE20DF1CD67D33FB6CC5DA519F69B11F3D48534074A83F03A5A9545427720A30A27432E94970155A026572E358072023061AF65A2A18E85", 16)
    print(f"{n=}\n{e=}\n")
    oaep(hashlib.sha256, b"8424462", n, 8) # (!, not compliant with RFC8017, because seedlength is not the length of the hashfunction)

def test():
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2: task83()
    elif sys.argv[1] == 'test': test()