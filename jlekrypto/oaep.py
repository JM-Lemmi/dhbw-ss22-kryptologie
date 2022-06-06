# Julian Lemmerich
# DHBW Mannheim, Kryptologe, Sommersemester 22

import os

#local imports
import mgf
import bytehelper
import rsa

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
    dbmask = mgf.mgf1(seed=seed, length=len(db), hash_func=mgf_hashfunc)
    if debug: print(f"{dbmask.hex()=}, {len(dbmask)=}")
    # 6. Apply the mask to the datablock
    maskeddb = bytehelper.bytes_xor(db, dbmask)
    if debug: print(f"{maskeddb.hex()=}")
    # 7. Generate a mask of length hlen for the seed
    seedmask = mgf.mgf1(seed=maskeddb, length=seedlen, hash_func=mgf_hashfunc)
    if debug: print(f"{seedmask.hex()=}")
    # 8. Apply the mask to the seed
    maskedseed = bytehelper.bytes_xor(seed, seedmask)
    if debug: print(f"{maskedseed.hex()=}")
    # 9. concatenate the masked seed and the masked db for encoded message
    em = b'\x00' + maskedseed + maskeddb
    if debug: print(f"{em.hex()=}")
    return em

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
    em_int = rsa.rsa(int.from_bytes(cm, byteorder="big"), d, n)
    em = bytehelper.bytes_from_int(em_int)
    if debug: print(f"{em.hex()=}, {len(em)=}")

    # Check if first byte of em is 0x00
    if em[:1] != 0: raise ValueError("First byte of em is not 0x00")
    # Split the message into seed and db
    maskedseedlen = mgf_hashfunc().digest_size
    maskedseed = em[1:1+maskedseedlen]
    maskeddb = em[1+maskedseedlen:]
    if debug: print(f"{maskedseed.hex()=}, {maskeddb.hex()=}")
    # generate the seed from the masked seed and masked DB
    seed = mgf.mgf1(maskeddb, maskedseedlen, mgf_hashfunc) ^ maskedseed
    if debug: print(f"{seed.hex()=}")
    # generate the DB from the seed and masked DB
    db = mgf.mgf1(seed, len(maskeddb), mgf_hashfunc) ^ maskeddb
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

def rsa_oaep(hash_func, m: bytes, n: int, e: int, seedlen=None, seed=None, debug=False) -> bytes:
    em = oaep(hash_func, m, n, seedlen=seedlen, seed=seed, debug=debug)
    if debug: print(f"{em.hex()=}")
    y: int; y = pow(int.from_bytes(em, byteorder='big'), e, n)
    if debug: print(f"{y=}")
    y_bytes= bytes.fromhex(hex(y)[2:])
    if debug: print(f"{y_bytes.hex()=}")
    return y_bytes #this fix is necessary to avoid int overflow?
