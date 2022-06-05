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

def oaep(mgf_hashfunc, m: bytes, n: int, seedlen: int=None, seed: bytes=None, debug=False) -> bytes:
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
    k = n.bit_length() // 8
    mlen = len(m)
    pslen = k - mlen - 2 - seedlen #TODO not sure if seedlen is correct here?
    ps = b'\x00' * pslen
    if debug: print(f"{k=}, {mlen=}, {pslen=}")
    # 3. Concatenate the the padding string, 0x01 and the message
    db = ps + b'\x01' + m
    if debug: print(f"{db.hex()=}, {len(db)=}")
    # 4. Generate a random seed of length from seedlen (should be mgf_hashfunc.digest_size)
    hlen = mgf_hashfunc().digest_size
    if seedlen is None: seedlen = hlen
    if seed is None: seed = os.urandom(seedlen)
    if debug: print(f"{seed.hex()=}, {seedlen=}, {hlen=}")
    # 5. Generate a mask of length of db using the MGF1 function
    dbmask = mgf1(seed=seed, length=len(db), hash_func=mgf_hashfunc)
    if debug: print(f"{dbmask.hex()=}, {len(dbmask)=}")
    # 6. Apply the mask to the datablock
    maskeddb = bytes_xor(db, dbmask)
    if debug: print(f"{maskeddb.hex()=}")
    # 7. Generate a mask of length hlen for the seed
    seedmask = mgf1(seed=maskeddb, length=seedlen, hash_func=mgf_hashfunc)
    if debug: print(f"{seedmask.hex()=}")
    # 8. Apply the mask to the seed
    maskedseed = bytes_xor(seed, seedmask)
    if debug: print(f"{maskedseed.hex()=}")
    # 9. concatenate the masked seed and the masked db for encoded message
    em = b'\x00' + maskedseed + maskeddb
    if debug: print(f"{em.hex()=}")
    return em

def rsa_oaep(hash_func, m: bytes, n: int, e: int, seedlen=None, seed=None, debug=False) -> bytes:
    em = oaep(hash_func, m, n, seedlen=seedlen, seed=seed, debug=debug)
    if debug: print(f"{em.hex()=}")
    y: int; y = pow(int.from_bytes(em, byteorder='big'), e, n)
    if debug: print(f"{y=}")
    y_bytes= bytes.fromhex(hex(y)[2:])
    if debug: print(f"{y_bytes.hex()=}")
    return y_bytes #this fix is necessary to avoid int overflow?

def task83(verbose=False, write_file=True):
    print("# Task 8.3)\n")
    # n & e have to be manually extracted from the pubkey with openssl:
    # openssl rsa -pubin -in "20220605_Übungsblatt8_pubkey.pub" -text -noout
    # openssl rsa -pubin -in "20220605_Übungsblatt8_pubkey.pub" -modulus -noout
    e = 65537
    n = int("AF5466C26A6B662AC98C06023501C9DF6036B065BD1F6804B1FC86307718DA4048211FD68A06917DE6F81DC018DCAF84B38AB77A6538BA2FE6664D3FB81E4A0886BBCDAB071AD6823FE20DF1CD67D33FB6CC5DA519F69B11F3D48534074A83F03A5A9545427720A30A27432E94970155A026572E358072023061AF65A2A18E85", 16)
    print(f"{n=}\n{e=}\n")
    encrypted_matrikelnr = rsa_oaep(hash_func=hashlib.sha256, m=b"8424462", n=n, e=e, seedlen=8) # (!, not compliant with RFC8017, because seedlength is not the length of the hashfunction)
    print(f"{encrypted_matrikelnr.hex()=}")
    # write to file
    if write_file:
        with open("20220605_Übungsblatt8_Aufgabe3_encrypted_matrikelnr.txt", "w") as f:
            f.write(encrypted_matrikelnr.hex())
            if verbose: print("sucessfully written to file")

def test():
    e = 65537
    n = int("AF5466C26A6B662AC98C06023501C9DF6036B065BD1F6804B1FC86307718DA4048211FD68A06917DE6F81DC018DCAF84B38AB77A6538BA2FE6664D3FB81E4A0886BBCDAB071AD6823FE20DF1CD67D33FB6CC5DA519F69B11F3D48534074A83F03A5A9545427720A30A27432E94970155A026572E358072023061AF65A2A18E85", 16)

    assert n.bit_length() / 8 == 128

    assert oaep(hashlib.sha256, m=bytes.fromhex("466f6f62617220313233343536373839"), n=n, seedlen=8, seed=bytes.fromhex("aa1122fe0815beef"), debug=True) == bytes.fromhex("00db2040f6425bb082ea600669f6f16b3a2ad05d4b6d9b23911c8cc432fddd8d34a68d88af3d787b7eebf6cd1b720812086758ce56e24ab819ccd8fb5eedb1cae9f6f895667d7f89d0454b828777ecabc040a649c8956e78ec1c721370663065cbc343deabad9eb6f2aceab6bfed5bea6543aa3672cddf915c5b564848f4e6ec")
    print("oaep test passed")

    assert rsa_oaep(hashlib.sha256, m=bytes.fromhex("466f6f62617220313233343536373839"), n=n, e=e, seedlen=8, seed=bytes.fromhex("aa1122fe0815beef"), debug=True) == bytes.fromhex("1b57819fa11340ac8b1843c87db7adb126daa8b6dde1feefd7af721cee8f46b6e2c361fc04ac055406a342187388b019dba0bc3f6503f267b848f7cc86b29a3d0b32730ccf04c5a8a3e1255708cbc6a6a648015e30f38b1c1c7aa9d2b0e67a775c7ad1cb72ff76c000af46e7cada3c3b45b5f4d1ec8e0596928cc9b46ee2b53d")

    print("tests passed")

if __name__ == "__main__":
    if len(sys.argv) < 2: task83()
    elif sys.argv[1] == 'test': test()
    elif sys.argv[1] == 'dryrun': task83(verbose=True, write_file=False)