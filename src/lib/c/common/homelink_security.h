#ifndef HOMELINK_SECURITY
#define HOMELINK_SECURITY

#ifdef __cplusplus
extern "C"
{
#endif

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

    extern const size_t RSA_KEY_SIZE;

    extern const size_t AES_KEY_SIZE;

    // uint16_t randomInt16();

    // uint32_t randomInt32();

    // Initializes rand() a local RSA public and private key.
    // RSA-2048 is used.
    extern bool initializeSecurity();

    // Cleans security variables.
    extern void cleanSecurity();

    // Generates an RSA-2048 keypair, initializeSecurity() must
    // be called prior to this function.
    extern bool generateRSAKeys(EVP_PKEY **keypair);

    // Writes the local RSA public key to a buffer, gives the length.
    extern void getRSAPublicKey(const EVP_PKEY *keypair, char *buffer, size_t *len);

    // Prints the local RSA public key.
    extern void printRSAPublicKey(const EVP_PKEY *keypair);

    // Writes n random bytes to a buffer.
    extern void randomBytes(uint8_t *buffer, int n);

    // Writes an AES key of the given size to a buffer.  Size is in bits,
    // not bytes.
    extern void generateAESKey(uint8_t *buffer, uint16_t keySize);

    // Encrypts a buffer with AES-GCM encryption with the given iv, writes
    // the validation tag to a buffer.
    extern bool aesEncrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen,
                           const uint8_t *key, const uint8_t *iv, uint8_t *tag);

    // Decrypts a buffer with AES-GCM encryption with the given iv and tag.
    extern bool aesDecrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen,
                           const uint8_t *key, const uint8_t *iv, uint8_t *tag);

    // Encrypts a buffer with RSA-2048 encryption with the given key.
    extern bool rsaEncrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen,
                           const char *key);

    // Decrypts a buffer with RSA-2048 encryption with the given key.
    extern bool rsaDecrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen,
                           EVP_PKEY *key);

    // Encrypts a session key with the given AES key, out and sessionKey
    // must point to buffers of at least 48 bytes
    extern bool encryptSessionKey(uint8_t *out, const char *sessionKey, const uint8_t *aesKey);

    // Decrypts a session key with the given AES key, sessionKey and in
    // must point to buffers of at least 48 bytes
    extern bool decryptSessionKey(char *sessionKey, uint8_t *in, const uint8_t *aesKey);

    // Returns a heap allocated string that represents the hash of the password.
    extern char *hashPassword(const char *password, size_t passwordLen);

    // // Returns a heap allocated string that represents the salted hash of the password.
    extern char *saltedHash(const char *password, size_t passwordLen, const char *salt,
                            size_t saltLen);

#ifdef __cplusplus
}
#endif

#endif
