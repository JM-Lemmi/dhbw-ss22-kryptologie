# Julian Lemmerich
# 27.04.2022
# Kryptologie
# Übungsblatt 3, Aufgabe 4.3

import hashlib

counter = 0
for i in range(0, 999999):
    string = "Julian Lemmerich " + str(i)
    hash = hashlib.md5(string.encode("utf-8")).hexdigest()
    if hash[:4] == "0000":
        print(hash + " " + string)
        counter = counter + 1
        if counter == 1: savedi = i

print()
print("Anzahl der Hashes beginnend mit '0000': " + str(counter))
print("Der niedrigste Zählerwert mit 'Julian Lemmerich' ist: " + str(savedi))

probability = counter / 1000000
print(f"Wahrscheinlichkeit: {probability*100:.5f}%")
print(f"Statistisch erwartete Wahrscheinlichkeit: {(1/65000)*100:.5f}%")

print()
print("Plausibilisierung:")
counter = 0
for i in range(0, 999999):
    string = "Albert Einstein " + str(i)
    hash = hashlib.md5(string.encode("utf-8")).hexdigest()
    if hash[:4] == "0000":
        print(hash + " " + string)
        if i == 113031:
            if counter == 0:
                print("Der niedrigste Zählwert bei Albert Einstein ist 113031, damit ist die Plausibilisierung korrekt.")
                break
