import numpy as np
from numpy.polynomial import Polynomial
from typing import Tuple

# Typing Definitions
Polynomial_Pair = Tuple[Polynomial, Polynomial]


class BGV:
    def __init__(self, polynomial_modulus: int, plaintext_modulus: int, ciphertext_modulus: int, seed=None):
        self.__rng = np.random.default_rng(seed)
        self.__n = polynomial_modulus
        self.__t = plaintext_modulus
        self.__q = ciphertext_modulus
        self.__mod_poly = Polynomial([1] + [0]*(polynomial_modulus - 1) + [1])

    # Internal Utility Functions
    def __coef_mod(self, polynomial: Polynomial, mod: int) -> Polynomial:
        """
        Applies modulus to all coefficients in a given Polynomial.
        :param polynomial: Polynomial to apply mod to
        :param mod: modulus value
        :return: new Polynomial instance
        """
        coef = []
        for c in polynomial.coef:
            coef.append(c % mod)

        return Polynomial(coef)

    def __gen_ternary_polynomial(self) -> Polynomial:
        """
        Generates a ternary polynomial of degree n, using a uniform distribution of coefficients in {-1, 0, 1}
        :return: ternary polynomial
        """
        return Polynomial(self.__rng.integers(-1, 2, self.__n))

    def __gen_error_term(self) -> Polynomial:
        """
        Generates a polynomial of degree n, with coefficients defined by a Gaussian distribution with parameters
        defined according to the homomorphic encryption standard: centered on 0, standard deviation of 8/sqrt(2*pi),
        and bounded by 6 standard deviations, rounded (+-19)
        :return: Polynomial instance of the error term
        """
        return Polynomial(np.round(self.__rng.normal(0, (8/np.sqrt(2*np.pi)), self.__n)))

    # Key Generation
    def generate_secret_key(self) -> Polynomial:
        """
        Generates a BGV Secret Key for use in BGV Encryption
        :return: Ternary Polynomial of degree n.
        """
        return self.__gen_ternary_polynomial()

    def generate_public_key(self, secret_key: Polynomial) -> Polynomial_Pair:
        """
        Generates BGV Public Key Polynomial Pair from a given Secret Key, for use in BGV Encryption.
        :param secret_key: Secret Key Polynomial from generate_secret_key()
        :return: Tuple of two Polynomial instances representing the Public Key
        """
        error_term = self.__gen_error_term()
        a = Polynomial(self.__rng.integers(0, self.__q, self.__n))  # Generates a polynomial of degree n with coefficients in {0, 1,...,q-1}

        pk1 = -1 * (a * secret_key + self.__t * error_term)         # Build Polynomial
        pk1 = pk1 % self.__mod_poly                                 # Apply polynomial modulus
        pk1 = self.__coef_mod(pk1, self.__q)                        # Apply coef modulus
        return pk1, a                                               # a is pk2

    def generate_evaluation_key(self, public_key: Polynomial_Pair, secret_key: Polynomial) -> Polynomial_Pair:
        """
        Generates a BGV Evaluation Key from a given Public Key and Secret Key.
        Used in Relinearization after Multiplication Evaluation with BGV Encryption.
        :param public_key: Public Key Polynomial Pair from generate_public_key()
        :param secret_key: Secret Key Polynomial from generate_secret_key()
        :return: Tuple of two Polynomial instances representing the Evaluation Key.
        """
        ek1 = (public_key[0] + secret_key ** 2) % self.__mod_poly
        ek1 = self.__coef_mod(ek1, self.__q)

        return ek1, public_key[1]

    # Encryption/Decryption
    def encrypt(self, message: Polynomial, public_key: Polynomial_Pair) -> Polynomial_Pair:
        """
        Encrypts a message using the BGV Encryption Scheme.
        :param message: Message to be encrypted, encoded as a Polynomial.
        :param public_key: Public Key Polynomial Pair used to encrypt the message
        :return: Tuple of two Polynomial instances representing the Ciphertext.
        """
        u = self.__gen_ternary_polynomial()
        error1 = self.__gen_error_term()
        error2 = self.__gen_error_term()

        c1 = public_key[0] * u + self.__t * error1 + message
        c1 = c1 % self.__mod_poly
        c1 = self.__coef_mod(c1, self.__q)

        c2 = public_key[1] * u + self.__t * error2
        c2 = c2 % self.__mod_poly
        c2 = self.__coef_mod(c2, self.__q)

        return c1, c2

    def decrypt(self, ciphertext: Polynomial_Pair, secret_key: Polynomial) -> Polynomial:
        """
        Decrypts a message using the BGV Encryption Scheme.
        :param ciphertext: Tuple of two Polynomials representing the Ciphertext
        :param secret_key: Polynomial Secret Key used to decrypt the ciphertext
        :return: Decrypted message, as a Polynomial instance.
        """
        message = (ciphertext[0] + ciphertext[1] * secret_key) % self.__mod_poly
        message = self.__coef_mod(message, self.__q)
        message = self.__coef_mod(message, self.__t)

        return message

    # Evaluation Methods
    def eval_add(self, c1: Polynomial_Pair, c2: Polynomial_Pair) -> Polynomial_Pair:
        """
        Adds two ciphertexts encrypted by the BGV Encryption Scheme.
        :param c1: First Ciphertext Polynomial Pair
        :param c2: Second Ciphertext Polynomial Pair
        :return: Tuple of two Polynomials representing the sum of the two ciphertexts.
        """
        # Note: An additional modulus operation with the polynomial modulus is omitted here for efficiency,
        #       as adding polynomials will never increase the degree of the polynomial beyond the highest
        #       degree among the terms.
        c3_1 = self.__coef_mod(c1[0] + c2[0], self.__q)
        c3_2 = self.__coef_mod(c1[1] + c2[1], self.__q)
        return c3_1, c3_2

    def __eval_mult(self, c1: Polynomial_Pair, c2: Polynomial_Pair) -> Tuple[Polynomial, Polynomial, Polynomial]:
        """
        Internal function to facilitate multiplying two ciphertexts. Requires Relinearization to be decrypted again.
        :param c1: First Ciphertext Polynomial Pair
        :param c2: Second Ciphertext Polynomial Pair
        :return: Tuple of three Polynomials representing the multiplication of the two ciphertexts.
        """
        mult1 = (c1[0] * c2[0]) % self.__mod_poly
        mult1 = self.__coef_mod(mult1, self.__q)

        mult2 = (c1[0] * c2[1] + c1[1] * c2[0]) % self.__mod_poly
        mult2 = self.__coef_mod(mult2, self.__q)

        mult3 = (c1[1] * c2[1]) % self.__mod_poly
        mult3 = self.__coef_mod(mult3, self.__q)

        return mult1, mult2, mult3

    def __relinearization(self, c: Tuple[Polynomial, Polynomial, Polynomial], evaluation_key: Polynomial_Pair) -> Polynomial_Pair:
        """
        Internal function to facilitate relinearization of ciphertext terms after Multiplication Evaluation.
        :param c: Tuple of three Polynomials to relinearize
        :param evaluation_key: Evaluation Key Polynomial Pair to facilitate relinearization
        :return: Tuple of two Polynomials representing a relinearized ciphertext
        """
        relin_1 = (c[0] + evaluation_key[0] * c[2]) % self.__mod_poly
        relin_1 = self.__coef_mod(relin_1, self.__q)

        relin_2 = (c[1] + evaluation_key[1] * c[2]) % self.__mod_poly
        relin_2 = self.__coef_mod(relin_2, self.__q)

        return relin_1, relin_2

    def eval_mult(self, c1: Polynomial_Pair, c2: Polynomial_Pair, evaluation_key: Polynomial_Pair) -> Polynomial_Pair:
        """
        Multiplies two ciphertexts encrypted by the BGV Encryption Scheme. Includes Relinearization after multiplication.
        :param c1: First Ciphertext Polynomial Pair
        :param c2: Second Ciphertext Polynomial Pair
        :param evaluation_key: Evaluation Key Polynomial Pair used to facilitate relinearization, from generate_evaluation_key()
        :return: Tuple of two Polynomials representing the multiplication of the two ciphertexts.
        """
        value = self.__eval_mult(c1, c2)
        value = self.__relinearization(value, evaluation_key)

        return value


# Encryption Parameters
n = 16      # Ring dimension (polynomial modulus)
t = 7       # plaintext modulus (coef modulus in plaintext)
q = 868     # ciphertext modulus (coef modulus in ciphertext)

# message
m = Polynomial([3, 2, 1] + [0]*(n-3))

bgv = BGV(n, t, q, 123)
s = bgv.generate_secret_key()
pk = bgv.generate_public_key(s)
ek = bgv.generate_evaluation_key(pk, s)

enc = bgv.encrypt(m, pk)
add = bgv.eval_add(enc, enc)
mult = bgv.eval_mult(enc, enc, ek)

dec_m = bgv.decrypt(enc, s)
dec_add = bgv.decrypt(add, s)
dec_mult = bgv.decrypt(mult, s)

print(m)
print("---")
print(dec_m)
print("---")
print(dec_add)
print("---")
print(dec_mult)
