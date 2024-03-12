"""
A primitive root modulo p is an integer g that generates all the numbers in the range of 1 to p-1 when raised to
different powers modulo p. In other words, for any number n between 1 and p-1, there exists a unique positive
integer r such that n = g^r (mod p).

A sequence (gr mod p) always repeats after some value of r, since mod p produces a finite number of values.
If g is a primitive root modulo p and p is prime, then the period of repetition is p−1. The last non-repeating digit
will always be 1. If 1 is first encountered before or after p-1 then it is not a primitive root.

Truth table: https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Table_of_primitive_roots
Primes < 100: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97
"""

import sympy

def is_primitive_root(g, p):
    """
    Check if the order of g modulo p is p-1.
    Returns True if the order is p-1, otherwise False.
    This only holds for primes so p is assumed to be a prime number.

    Deprecated in favour of using sympy
    """
    # search r in 1 to p-1
    for r in range(1, p):
        # compute g^r mod p
        gr = pow(g, r, p)
        if gr == 1:
            # if 1 is found at exactly p-1 its primitive
            if r == p-1:
                return True
            # if 1 is found earlier then p-1 its not primitive
            # this is still required to filter repetitions earlier than p-1
            else:
                return False

def primRoots(p):
    if not sympy.isprime(p):
        raise RuntimeError("Non-prime input")
    
    # Find all the generators of p by brute force
    roots = []
    for g in range(1, p):
        # sympy.n_order(g, p) == sympy.totient(p)
        if sympy.ntheory.residue_ntheory.is_primitive_root(g, p):
            roots.append(g)

    print(p, roots)
    return roots


if __name__ == "__main__":
    # primes
    assert primRoots(2) == [1]
    assert primRoots(3) == [2]
    assert primRoots(5) == [2, 3]
    assert primRoots(7) == [3, 5]
    assert primRoots(11) == [2, 6, 7, 8]
    assert primRoots(13) == [2, 6, 7, 11]
    assert primRoots(17) == [3, 5, 6, 7, 10, 11, 12, 14]
    assert primRoots(19) == [2, 3, 10, 13, 14, 15]
    assert primRoots(23) == [5, 7, 10, 11, 14, 15, 17, 19, 20, 21]
    assert primRoots(29) == [2, 3, 8, 10, 11, 14, 15, 18, 19, 21, 26, 27]
    assert primRoots(31) == [3, 11, 12, 13, 17, 21, 22, 24]
