# Julian Lemmerich
# 28.04.2020
# Kryptologie
# Übungsblatt 3
# Aufgabe 4.1

def divisors(n):
    return [i for i in range(1, n+1) if n % i == 0]

print("Aufgabe 4.1a)")
for m in {33, 37}:
    for k in divisors(718):
        if pow(m, k, 719) == 1:
            print(f"Die Ordnung von m und k ist: m = {m}, k = {k}")
            break

print("\nAufgabe 4.1b)")
p = 719
g = 33
a = 293
b = 174
alpha = pow(g, a, p)
print(f"pubkey von Alice: {alpha}")
beta = pow(g, b, p)
print(f"pubkey von Bob: {beta}")
print("shared key (should match): " + str(pow(alpha, b, p)) + ", " + str(pow(beta, a, p)))

print("\nAufgabe 4.1c)")
p = 719
g = 37
a = 293
b = 174
alpha = pow(g, a, p)
print(f"pubkey von Alice: {alpha}")
beta = pow(g, b, p)
print(f"pubkey von Bob: {beta}")
print("shared key (should match): " + str(pow(alpha, b, p)) + ", " + str(pow(beta, a, p)))