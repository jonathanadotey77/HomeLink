#ifndef HOMELINK_SECURITY
#define HOMELINK_SECURITY

#ifdef __cplusplus
extern "C"
{
#endif

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

    // uint16_t randomInt16();

    // uint32_t randomInt32();

    // Initializes rand() a local RSA public and private key.
    // RSA-2048 is used.
    bool initializeSecurity();

    // Cleans security variables.
    void cleanSecurity();

    // Writes the local RSA public key to a buffer, gives the length.
    void getRSAPublicKey(char *buffer, size_t *len);

    // Prints the local RSA public key.
    void printRSAPublicKey();

    // Writes n random bytes to a buffer.
    void randomBytes(uint8_t *buffer, int n);

    // Writes an AES key of the given size to a buffer.  Size is in bits,
    // not bytes.
    void generateAESKey(uint8_t *buffer, uint16_t keySize);

    // Encrypts a buffer with AES-GCM encryption with the given iv and tag.
    bool aesEncrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen,
                    const uint8_t *key, const uint8_t *iv, uint8_t *tag);

    // Decrypts a buffer with AES-GCM encryption with the given iv and tag.
    bool aesDecrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen,
                    const uint8_t *key, const uint8_t *iv, uint8_t *tag);

    // Encrypts a buffer with RSA-2048 encryption with the given key.
    bool rsaEncrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen,
                    const char *key);

    // Decrypts a buffer with RSA-2048 encryption with the given key.
    bool rsaDecrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen,
                    const char *key);

    // Returns a heap allocated string that represents the hash of the password.
    char *hashPassword(const char *password, size_t passwordLen);

    // // Returns a heap allocated string that represents the salted hash of the password.
    char *saltedHash(const char *password, size_t passwordLen, const char *salt,
                     size_t saltLen);

    // Gives a random port within the given range, inclusive.
    uint16_t randomPort(uint16_t lowerBound, uint16_t upperBound);

#ifdef __cplusplus
}
#endif

#endif
