# Julian Lemmerich
# DHBW-Mannheim, Kryptologie
# Übungsblatt 4
# Montgomery Ladder

# this function removes leading 0 from the native bit vector
intToBitsNoZero <- function(x) {
    x_bits <- intToBits(x)
    for (i in length(x_bits):1) {
        if (x_bits[i] == 1) {
            x_newbits <- x_bits[1:i]
            break
        }
    }
    return(x_newbits)
}

# This function calculates x=a^k mod n.
# Function signature is the same as pythons pow function.
montladder <- function(a, k, n, verbose=FALSE) {
    k_bits <- intToBitsNoZero(k)
    l <- length(k_bits)
    if (verbose==TRUE) {print(paste0("Length of k: ", l))}
    x_i <- 1
    y_i <- mod(a, n)
    # Iterate over the bits of k. (Array indices in R start at 1)
    for (i in l:1) {
        x_iplus1 <- x_i
        y_iplus1 <- y_i
        b_i <- k_bits[i]
        if (b_i == 0) {
            x_i <- mod(x_iplus1^2, n)
            y_i <- mod(x_iplus1 * y_iplus1, n)
        } else if (b_i == 1) {
            x_i <- mod(x_iplus1 * y_iplus1, n)
            y_i <- mod(y_iplus1^2, n)
        }
        if (verbose==TRUE) {print(paste0(i-1, ": b_", i-1, " = ", b_i, ", x_", i-1, " = ", x_i, ", y_", i-1, " = ", y_i))}
    }
    print(paste0("x_0 = ", x_i))
    return(x_i)
}


## Aufgabenblatt

print("Aufgabe 4.1b)")
print("x = 8421^1111 mod 9533")
print(paste0("x = ", montladder(8421, 1111, 9533, verbose=TRUE)))

print("Aufgabe 4.3")
a <- sample(1:1110, 1)[1]
p <- 1111
print(paste0("a = ", a))
x <- montladder(a, p-1, p, verbose=TRUE)
print(paste0("a^(p-1) = ", x, " (mod ", p, ")"))
if (x != 1) {
    print(paste0("Der Fermat-Test zeigt, dass ", p, " nicht prim ist, da a^(p-1) != 1"))
}
