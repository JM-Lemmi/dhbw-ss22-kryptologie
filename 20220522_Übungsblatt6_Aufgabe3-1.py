# Julian Lemmerich
# Kryptologie, DHBW Mannheim
# Übungsblatt 6
# Aufgabe 3

def pbox_aufgabe631(x):
    # ungerade bits bleiben, gerade bits werden um 2 nach links verschoben
    return ((x & 0x54) >> 2) | (x & 0xaa) | ((x & 1) << 6)
