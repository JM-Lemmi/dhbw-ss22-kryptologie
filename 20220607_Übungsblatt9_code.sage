# Julian Lemmerich
# DHBW Mannheim Kryptologie
# Übungsblatt 9

import sys
import hashlib

def decode_point(d, p):
    """decodes uncompressed generator point from openssl output
    
    Arguments:
        d {int} -- uncompressed point
        p {int} -- prime
    
    Returns:
        int, int -- generator point
    """
    x_len = ceil(log(p, 2)/8)
    x = int(d[2:2+x_len*2], 16)
    y = int(d[2+x_len*2:], 16)
    return x, y


def task93():
    # openssl ecparam -name secp256r1 -param_enc explicit -text -noout
    p = int("00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    a = int("00ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
    b = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    g = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    n = int("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    h = 1
    g_x, g_y = decode_point(g, p)
    P256 = EllipticCurve(GF(p), [0,0,0, a, b])
    G = P256(g_x, g_y)
    # openssl ec -pubin -noout -text -conv_form uncompressed
    q = "048c3aa86d54441a69d3a30c788e5674844ab298253b92f1673e2de534ee98f79d511ef4818b008be75c727ca3dde25c98281b75cea75b6969bd83ebae3e3518f6"
    q_x, q_y = decode_point(q, p)
    Q = P256(q_x, q_y)

    # Message
    m = b"Kryptologie DHBW Mannheim"

    # openssl asn1parse -inform DER -in 20220613_Übungsblatt9_signature.bin -i
    r = int("4854A53830FAB30CAC49C91B72E7F84D8CB25102DB220F6DC7F1A8B31B29B913", 16)
    s = int("86ABF01F3AFF9B2A0B3823F2581983A8C38264660EC66BB2F8C648BEE88D36E0", 16)

    # RFC3279, 2.2.3
    e = int.from_bytes(hashlib.sha256(m).digest(), 'big')
    w = pow(s, -1, n)
    u_1 = int((e * w) % n)
    u_2 = int((r * w) % n)

    P = (u_1 * G) + (u_2 * Q)

    if P[0] == r:
        print("Signature valid")
    else:
        print("Signature invalid")

def task94():
    m_1 = b"Kryptologie DHBW Mannheim"
    r_1 = int("6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569", 16)
    s_1 = int("c8c8510ee5ec5b9c25d19354856a4fcd576ed2d3070219386172cb2f593c7efd", 16)
    m_2 = b"Kryptologie DHBW Mannheim 2022"
    r_2 = int("6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569", 16)
    s_2 = int("8ad156e23cf73f0c86c074e17404f863802f3ae0ca125599a242b24919dcf0f7", 16)

    # openssl ecparam -name secp256r1 -param_enc explicit -text -noout
    n = int("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    assert r_1 == r_2

    e_1 = int.from_bytes(hashlib.sha256(m_1).digest(), 'big')
    e_2 = int.from_bytes(hashlib.sha256(m_2).digest(), 'big')

    d = int(((s_2 * e_1 - s_1 * e_2) * pow(s_1 * r_1 - s_2 * r_1, -1, n)) % n)

    print(f"Private key (int): {d}\nSecret message: {bytes.fromhex(hex(d)[2:]).decode()}")

def main(verbose=False):
    task93()
    task94

if __name__ == "__main__":
    if len(sys.argv) < 2: main()
    elif sys.argv[1] == '93': task93()
    elif sys.argv[1] == '94': task94()