#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <pkcs11.h>

void positive(RSA *rsa, EVP_PKEY_CTX *ctx, unsigned char *in, unsigned char *out, int len) {
    RSA_private_decrypt(len, in, out, rsa, RSA_NO_PADDING); /* EXPECT:raw-rsa-openssl-no-padding-private */
    RSA_private_encrypt(len, in, out, rsa, RSA_NO_PADDING); /* EXPECT:raw-rsa-openssl-no-padding-private */
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING); /* EXPECT:raw-rsa-openssl-evp-no-padding */
    CK_MECHANISM mech = { CKM_RSA_X_509, NULL, 0 }; /* EXPECT:raw-rsa-pkcs11-ckm-rsa-x-509 */
}

void negative(RSA *rsa, EVP_PKEY_CTX *ctx, unsigned char *in, unsigned char *out, int len) {
    RSA_private_decrypt(len, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_public_encrypt(len, in, out, rsa, RSA_NO_PADDING);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
    CK_MECHANISM pss = { CKM_RSA_PKCS_PSS, NULL, 0 };
}
