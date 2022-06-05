# Julian Lemmerich
# DHBw Mannheim Kryptologie
# Übungsblatt 8 Aufgabe 3

import sys
import hashlib
import os

# from https://techoverflow.net/2020/09/27/how-to-fix-python3-typeerror-unsupported-operand-types-for-bytes-and-bytes/
def bytes_xor(a: bytes, b: bytes) -> bytes:
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

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

def oaep(mgf_hashfunc, m: bytes, n: int, seedlen: int=None, seed: bytes=None) -> bytes:
    """" OAEP Encoding

    Implementation without authenticated data L. (!, not compliant with RFC8017)
    seedlength is the length of the seed used in the mask generation function. Should be mgf_hashfunc.digest_size

    Arguments:
        mgf {hashlib.func} -- mask generation function
        m {bytes} -- message to be encoded
        n {int} -- modulus

    Optional Arguments:
        seedlen {int} -- length of the seed for mgf, overrides the hash function length
        seed {bytes} -- fixed seed for mgf, only for testing purposes!
    """

    # 2. Generate a pading string
    k = n.bit_length()
    mlen = len(m)
    pslen = k - mlen - 2
    ps = b'\x00' * pslen
    # 3. Concatenate the the padding string, 0x01 and the message
    db = ps + b'\x01' + m
    # 4. Generate a random seed of length from seedlen (should be mgf_hashfunc.digest_size)
    hlen = mgf_hashfunc().digest_size
    if seedlen is None: seedlen = hlen
    if seed is None: seed = os.urandom(seedlen)
    # 5. Generate a mask of length of db using the MGF1 function
    dbmask = mgf1(seed=seed, length=len(db), hash_func=mgf_hashfunc)
    # 6. Apply the mask to the datablock
    maskeddb = bytes_xor(db, dbmask)
    # 7. Generate a mask of length hlen for the seed
    seedmask = mgf1(seed=maskeddb, length=hlen, hash_func=mgf_hashfunc)
    # 8. Apply the mask to the seed
    maskedseed = bytes_xor(seed, seedmask)
    # 9. concatenate the masked seed and the masked db for encoded message
    em = b'\x00' + maskedseed + maskeddb
    return em

def rsa(hash_func, m, n, e, seedlen=None):
    em = oaep(hash_func, m, n, seedlen=seedlen)
    d = pow(e, -1, n)
    return pow(int(m), d, n)

def task83(verbose=False, write_file=True):
    print("# Task 8.3)\n")
    # n & e have to be manually extracted from the pubkey with openssl:
    # openssl rsa -pubin -in "20220605_Übungsblatt8_pubkey.pub" -text -noout
    # openssl rsa -pubin -in "20220605_Übungsblatt8_pubkey.pub" -modulus -noout
    e = 65537
    n = int("AF5466C26A6B662AC98C06023501C9DF6036B065BD1F6804B1FC86307718DA4048211FD68A06917DE6F81DC018DCAF84B38AB77A6538BA2FE6664D3FB81E4A0886BBCDAB071AD6823FE20DF1CD67D33FB6CC5DA519F69B11F3D48534074A83F03A5A9545427720A30A27432E94970155A026572E358072023061AF65A2A18E85", 16)
    print(f"{n=}\n{e=}\n")
    encrypted_matrikelnr = rsa(hashlib.sha256, b"8424462", n, 8) # (!, not compliant with RFC8017, because seedlength is not the length of the hashfunction)
    print(f"{encrypted_matrikelnr=}")
    # write to file
    if write_file:
        with open("20220605_Übungsblatt8_Aufgabe3_encrypted_matrikelnr.txt", "wb") as f:
            f.write(encrypted_matrikelnr)
            if verbose: print("sucessfully written to file")

def test():
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2: task83()
    elif sys.argv[1] == 'test': test()
    elif sys.argv[1] == 'dryrun': task83(verbose=True, write_file=False)