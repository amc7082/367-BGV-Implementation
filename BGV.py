import numpy as np
from numpy.polynomial import Polynomial

rng = np.random.default_rng(123)


def coef_mod(polynomial, mod):
    coef = []
    for c in polynomial.coef:
        coef.append(c % mod)

    return Polynomial(coef)


# Encryption Parameters
n = 16      # Ring dimension (polynomial modulus)
t = 7       # plaintext modulus (coef modulus in plaintext)
q = 868     # ciphertext modulus (coef modulus in ciphertext)

# Polynomial generator functions
def gen_modulus_polynomial(_n):
    return Polynomial([1] + [0]*(_n-1) + [1])


def gen_secret_key(_n):
    return Polynomial(rng.integers(-1, 2, _n))


def gen_error_term(_n):
    return Polynomial(np.round(rng.normal(0, (8/np.sqrt(2*np.pi)), _n)))


def public_key_gen(_q, _n, _t, _secret_key, _error_term, _mod_poly):
    a = Polynomial(rng.integers(0, _q, _n))
    pk1 = -1 * (a * _secret_key + _t * _error_term)     # Build Polynomial
    pk1 = pk1 % _mod_poly                               # Apply polynomial modulus
    pk1 = coef_mod(pk1, _q)                             # Apply coef modulus
    return pk1, a                                       # a is pk2


