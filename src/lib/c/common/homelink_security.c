#include <homelink_security.h>

#include <homelink_packet.h>
#include <homelink_misc.h>

#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t RSA_KEY_SIZE = 2048U;

static bool randInitialized = false;
static EVP_PKEY *keypair = NULL;

static volatile bool initialized = false;

bool initializeSecurity()
{
    if (initialized)
    {
        return true;
    }

    srand(time(NULL));

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
    {
        fprintf(stderr, "Could not create context\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    int rc = 0;
    rc = EVP_PKEY_keygen_init(ctx);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not initialize keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set keygen bits\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    rc = EVP_PKEY_keygen(ctx, &keypair);
    if (rc <= 0)
    {
        fprintf(stderr, "Could generate RSA keys\n");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    initialized = true;

    return true;
}

void cleanSecurity()
{
    EVP_PKEY_free(keypair);
    EVP_cleanup();
    ERR_free_strings();
}

void getRSAPublicKey(char *buffer, size_t *len)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_PUBKEY(bio, keypair))
    {
        return;
    }

    char *publicKey = NULL;
    *len = BIO_get_mem_data(bio, &publicKey);
    memcpy(buffer, publicKey, *len);
    buffer[*len] = '\0';

    BIO_free_all(bio);
}

void printRSAPublicKey()
{
    char key[512] = {0};
    size_t len = 0;

    getRSAPublicKey(key, &len);

    printf("Key: %s\n", key);
    printf("Len: %d\n", (int)len);
}

void randomBytes(uint8_t *buffer, int n)
{
    if (!randInitialized)
    {
        RAND_poll();
        randInitialized = true;
    }
    RAND_bytes(buffer, n);
}

void generateAESKey(uint8_t *buffer, uint16_t keySize)
{
    randomBytes(buffer, (int)(keySize / 8));
}

bool aesEncrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen, const uint8_t *key, const uint8_t *iv, uint8_t *tag)
{
    int rc = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Could not create ctx in aesEncrypt()\n");
        return false;
    }

    rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set cipher in aesEncrypt()\n");
        return false;
    }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set IV length in aesEncrypt()\n");
        return false;
    }

    rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set key and IV in aesEncrypt()\n");
        return false;
    }

    rc = EVP_EncryptUpdate(ctx, out, outLen, in, inLen);
    if (rc <= 0)
    {
        fprintf(stderr, "EncryptUpdate failed in aesEncrypt()\n");
        return false;
    }

    uint8_t *temp = malloc(*outLen);
    int tempLen = *outLen;

    rc = EVP_EncryptFinal(ctx, temp, &tempLen);
    free(temp);
    if (rc <= 0)
    {
        fprintf(stderr, "EncryptFinal failed in aesEncrypt()\n");
        return false;
    }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not get tag in aesEncrypt()\n");
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aesDecrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen, const uint8_t *key, const uint8_t *iv, uint8_t *tag)
{
    int rc = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Could not create ctx in aesDecrypt()\n");
        return false;
    }

    rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set cipher in aesDecrypt()\n");
        return false;
    }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set IV length in aesDecrypt()\n");
        return false;
    }

    rc = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set key and IV in aesDecrypt()\n");
        return false;
    }

    rc = EVP_DecryptUpdate(ctx, out, outLen, in, inLen);
    if (rc <= 0)
    {
        fprintf(stderr, "DecryptUpdate failed in aesDecrypt()\n");
        return false;
    }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set tag in aesDecrypt()\n");
        return false;
    }

    rc = EVP_DecryptFinal(ctx, out, outLen);
    if (rc <= 0)
    {
        fprintf(stderr, "DecryptFinal failed in aesDecrypt()\n");
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool rsaEncrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen, const char *rsaPublicKey)
{
    BIO *bio = BIO_new_mem_buf(rsaPublicKey, strlen(rsaPublicKey) + 1);
    EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (ctx == NULL)
    {
        fprintf(stderr, "Could not create ctx in rsaEncrypt()\n");
        EVP_PKEY_free(publicKey);
        return false;
    }

    BIO_free_all(bio);

    int rc = 0;

    rc = EVP_PKEY_encrypt_init(ctx);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not initialize encryption in rsaEncrypt()\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set padding in rsaEncrypt()\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }

    rc = EVP_PKEY_encrypt(ctx, out, outLen, in, inLen);
    if (rc <= 0)
    {
        fprintf(stderr, "Encryption failed in rsaEncrypt()\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(publicKey);
    return true;
}

bool rsaDecrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen, const char *rsaPublicKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    if (rsaPublicKey == NULL)
    {
        ctx = EVP_PKEY_CTX_new(keypair, NULL);
        if (ctx == NULL)
        {
            fprintf(stderr, "Could not create ctx in rsaDecrypt()\n");
            return false;
        }
    }
    else
    {
        BIO *bio = BIO_new_mem_buf(rsaPublicKey, -1);
        EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, NULL);
        if (ctx == NULL)
        {
            fprintf(stderr, "Could not create ctx in rsaDecrypt()\n");
            EVP_PKEY_free(publicKey);
            return false;
        }

        BIO_free_all(bio);
    }

    int rc = 0;

    rc = EVP_PKEY_decrypt_init(ctx);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not initialize decryption in rsaDecrypt()\n");
        return false;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (rc <= 0)
    {
        fprintf(stderr, "Could not set padding in rsaDecrypt()\n");
        return false;
    }

    rc = EVP_PKEY_decrypt(ctx, out, outLen, in, inLen);
    if (rc <= 0)
    {
        fprintf(stderr, "Decryption failed in rsaDecrypt()\n");
        ERR_print_errors_fp(stderr);

        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

char *hashPassword(const char *password, size_t passwordLen)
{
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    OpenSSL_add_all_algorithms();
    md = EVP_get_digestbyname("sha256");

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, passwordLen);
    EVP_DigestFinal_ex(mdctx, digest, &md_len);
    EVP_MD_CTX_free(mdctx);

    char *hashedPassword = malloc(SHA256_DIGEST_LENGTH * 2 + 1);

    getByteStr(hashedPassword, digest, sizeof(digest));

    hashedPassword[SHA256_DIGEST_LENGTH * 2] = '\0';

    return hashedPassword;
}

char *saltedHash(const char *password, size_t passwordLen, const char *salt, size_t saltLen)
{
    size_t len = passwordLen + saltLen;
    char *saltedPassword = malloc(len + 1);

    strncpy(saltedPassword, password, passwordLen);
    strncpy(saltedPassword + passwordLen, salt, saltLen);
    saltedPassword[len] = '\0';

    char *out = hashPassword(saltedPassword, len);
    free(saltedPassword);

    return out;
}

uint16_t randomPort(uint16_t lowerBound, uint16_t upperBound)
{
    uint32_t range = (uint32_t)upperBound - (uint32_t)lowerBound + 1;
    uint32_t idx = (uint32_t)rand() % range;
    return lowerBound + (uint16_t)idx;
}
