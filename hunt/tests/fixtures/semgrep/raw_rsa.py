import gmpy2
import pkcs11
import PyKCS11
import blind_rsa_signatures  # EXPECT:raw-rsa-blind-signature-library


def positive(key, rsa_key, crypto_key, x, n, session):
    s1 = pow(x, key.d, key.n)  # EXPECT:raw-rsa-python-pow-private-exponent
    s2 = pow(x, crypto_key.private_numbers().d, n)  # EXPECT:raw-rsa-python-pow-private-exponent
    s3 = gmpy2.powmod(x, key.d, key.n)  # EXPECT:raw-rsa-python-pow-private-exponent
    s4 = rsa_key._decrypt(x)  # EXPECT:raw-rsa-pycryptodome-private-primitive
    m = PyKCS11.Mechanism(PyKCS11.CKM_RSA_X_509, None)  # EXPECT:raw-rsa-python-pkcs11-mechanism
    s5 = key.sign(x, mechanism=pkcs11.Mechanism.RSA_X_509)  # EXPECT:raw-rsa-python-pkcs11-mechanism
    return s1, s2, s3, s4, m, s5


def negative(key, x, session):
    v = pow(x, key.e, key.n)
    s = key.sign(x, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS_PSS)
    m = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
    return v, s, m
