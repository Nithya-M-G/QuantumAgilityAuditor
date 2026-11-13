// Device firmware signing - keys live in the field for 20 years.
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

RSA *provision_root_key(void) {
    RSA *root = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(root, 2048, e, NULL);
    return root;
}

EC_KEY *provision_device_key(void) {
    EC_KEY *device = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(device);
    return device;
}

void image_digest(const unsigned char *data, size_t len, unsigned char *out) {
    SHA1_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(out, &ctx);
}
