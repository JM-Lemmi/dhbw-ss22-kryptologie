# Julian Lemmerich
# Kryptologie, DHBW Mannheim
# 22.05.2022

def choose_b (p, verbose=False):
    b=2
    while pow(b, (p-1)//2, p) == 1:
        b = b+1
    
    if verbose: print(f"{b=}")
    return b

def sqrt_elcurve_notby4(x, p, l, t, verbose=False):
    # dieser Algorithmus ist, wenn p+1 nicht durch 4 teilbar ist.
    """
    Berechnet die Quadratwurzel von x im Körper p, wenn p+1 nicht durch 4 teilbar ist.
    Benötigt außerdem die parameter l, t
    """

    b = choose_b(p, verbose)

    if p+1 % 4 == 0: raise ValueError("p+1 ist durch 4 teilbar")

    if pow(x, int((p-1)/2), p) != 1:
        raise ValueError(f"{x} ist nicht quadratisch")

    n = 0
    i = 0
    c = 0

    while i < l:
        c = (x ** (2 ** (l-(i+1)) * t) * pow(b, n, p)) % p
        if (c == 1):
            n = (n/2) % p
        else:
            n = (n/2 + (p-1)/4) % p
        n = int(n)
        print(f"Loop {i} beendet. c_{i} = {c}, n_{i+1} = {n}")
        i = i+1

    a = (pow(x, (t+1)//2, p) * pow(b, n, p)) % p
    assert pow(a, 2, p) == x

    if verbose: print(f"{a=}")
    return a

def main():
    p = 617
    l = 2
    t = 77
    # elliptic curve values!
    a = 27
    b = 133

    for x in [100, 200, 400, 600]:
        print(f"\n### {x=}\n")
        ysquared = (pow(x, 3, p) + a * x + b) % p
        print(f"y^2 = {ysquared}")
        try:
            y = sqrt_elcurve_notby4(ysquared, p, l, t, verbose=True)
            print(f"\n{ysquared} ist ein Quadrat in F_{p}. {y=}")
            print(f"\nEs gibt die Punkte ({x}|{y}) und ({x}|{(p-y)%p}) auf E.")
        except ValueError as e:
            print(f"\n{e}")
            print(f"\nEs gibt keinen Punkt auf E mit {x=}")

if __name__ == "__main__":
    main()