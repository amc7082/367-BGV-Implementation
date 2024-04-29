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

# message
m = Polynomial([3, 2, 1] + [0]*(n-3))


# Polynomial generator functions
def gen_modulus_polynomial(_n):
    return Polynomial([1] + [0]*(_n-1) + [1])


def gen_ternary_polynomial(_n):
    return Polynomial(rng.integers(-1, 2, _n))


def gen_error_term(_n):
    return Polynomial(np.round(rng.normal(0, (8/np.sqrt(2*np.pi)), _n)))


def public_key_gen(_q, _n, _t, _secret_key, _error_term, _mod_poly):
    a = Polynomial(rng.integers(0, _q, _n))
    pk1 = -1 * (a * _secret_key + _t * _error_term)     # Build Polynomial
    pk1 = pk1 % _mod_poly                               # Apply polynomial modulus
    pk1 = coef_mod(pk1, _q)                             # Apply coef modulus
    return pk1, a                                       # a is pk2


def evaluation_key_gen(_public_key, _secret_key, _q, _mod_poly):
    ek1 = (_public_key[0] + _secret_key**2) % _mod_poly
    ek1 = coef_mod(ek1, _q)

    return ek1, _public_key[1]


# Encryption/Decryption functions
def _bgv_encrypt(_message, _public_key, _q, _t, _u, _error1, _error2, _mod_poly):
    c1 = _public_key[0] * _u + _t * _error1 + _message
    c1 = c1 % _mod_poly
    c1 = coef_mod(c1, _q)

    c2 = _public_key[1] * _u + _t * _error2
    c2 = c2 % _mod_poly
    c2 = coef_mod(c2, _q)

    return c1, c2


def bgv_encrypt(_message, _public_key, _q, _t, _n):
    u = gen_ternary_polynomial(_n)
    error1 = gen_error_term(_n)
    error2 = gen_error_term(_n)
    mod_poly = gen_modulus_polynomial(_n)

    return _bgv_encrypt(_message, _public_key, _q, _t, u, error1, error2, mod_poly)


def _bgv_decrypt(_ciphertext, _secret_key, _q, _t, _mod_poly):
    message = _ciphertext[0] + _ciphertext[1] * _secret_key
    message = message % _mod_poly
    message = coef_mod(message, _q)
    message = coef_mod(message, _t)

    return message


def bgv_decrypt(_ciphertext, _secret_key, _q, _t, _n):
    mod_poly = gen_modulus_polynomial(_n)

    return _bgv_decrypt(_ciphertext, _secret_key, _q, _t, mod_poly)


# Evaluation Functions
def bgv_add(_c1, _c2, _q):
    c3_1 = coef_mod(_c1[0] + _c2[0], _q)
    c3_2 = coef_mod(_c1[1] + _c2[1], _q)
    return c3_1, c3_2


def _bgv_mult(_c1, _c2, _q, _mod_poly):
    mult1 = (_c1[0] * _c2[0]) % _mod_poly
    mult1 = coef_mod(mult1, _q)

    mult2 = (_c1[0] * _c2[1] + _c1[1] * _c2[0]) % _mod_poly
    mult2 = coef_mod(mult2, _q)

    mult3 = (_c1[1] * _c2[1]) % _mod_poly
    mult3 = coef_mod(mult3, _q)

    return mult1, mult2, mult3


def _bgv_relinearization(_c, _evaluation_key, _q, _mod_poly):
    relin_1 = (_c[0] + _evaluation_key[0] * _c[2]) % _mod_poly
    relin_1 = coef_mod(relin_1, _q)

    relin_2 = (_c[1] + _evaluation_key[1] * _c[2]) % _mod_poly
    relin_2 = coef_mod(relin_2, _q)

    return relin_1, relin_2


def bgv_mult(_c1, _c2, _evaluation_key, _q, _n):
    mod_poly = gen_modulus_polynomial(_n)
    mult = _bgv_mult(_c1, _c2, _q, mod_poly)
    mult = _bgv_relinearization(mult, _evaluation_key, _q, mod_poly)

    return mult


s = gen_ternary_polynomial(n)
pk = public_key_gen(q, n, t, s, gen_error_term(n), gen_modulus_polynomial(n))
ek = evaluation_key_gen(pk, s, q, gen_modulus_polynomial(n))
cipher1 = bgv_encrypt(m, pk, q, t, n)
cipher2 = bgv_encrypt(m, pk, q, t, n)
evaluated = bgv_mult(cipher1, cipher1, ek, q, n)

dec_m = bgv_decrypt(evaluated, s, q, t, n)

print(m)
print("---")

print("---")
print(dec_m)
