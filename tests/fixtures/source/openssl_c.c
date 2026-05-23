/* openssl_c.c — fixture for acdi source scanner tests */
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/* Generate RSA-2048 key pair */
RSA *make_rsa(void) {
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    return rsa;
}

/* Create P-256 EC key */
EC_KEY *make_ec(void) {
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}

/* Encrypt with AES-256-CBC */
void encrypt_data(EVP_CIPHER_CTX *ctx) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
}

/* Digest with SHA-1 (deprecated) */
void hash_data(const unsigned char *data, size_t len) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    EVP_Digest(data, len, digest, NULL, EVP_sha1(), NULL);
}
