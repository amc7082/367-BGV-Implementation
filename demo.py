from numpy.polynomial import Polynomial
import BGV

# Encryption Parameters
n = 16      # Ring dimension (polynomial modulus)
t = 7      # plaintext modulus (coef modulus in plaintext)
q = 868     # ciphertext modulus (coef modulus in ciphertext)

# Initialize BGV system
bgv = BGV.BGV(n, t, q, 123)
s = bgv.generate_secret_key()
pk = bgv.generate_public_key(s)
ek = bgv.generate_evaluation_key(pk, s)

# Addition demo
m1 = Polynomial([3, 2, 1] + [0]*(n-3))
m2 = Polynomial([2, 1, 3] + [0]*(n-3))

c1 = bgv.encrypt(m1, pk)
c2 = bgv.encrypt(m2, pk)
c3 = bgv.eval_add(c1, c2)
m3 = bgv.decrypt(c3, s)

print(m3)

# Multiplication demo
m1 = Polynomial([1, 1, 1] + [0]*(n-3))
m2 = Polynomial([1, 2, 2] + [0]*(n-3))

c1 = bgv.encrypt(m1, pk)
c2 = bgv.encrypt(m2, pk)
c3 = bgv.eval_mult(c1, c2, ek)
m3 = bgv.decrypt(c3, s)

print(m3)
