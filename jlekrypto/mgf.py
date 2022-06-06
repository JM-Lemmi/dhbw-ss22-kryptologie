# Julian Lemmerich
# DHBW Mannheim, Kryptologie, Sommersemester 22

import hashlib

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