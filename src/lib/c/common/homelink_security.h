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

    bool initializeSecurity();

    void cleanSecurity();

    void getRSAPublicKey(char *buffer, size_t *len);

    void printRSAPublicKey();

    void randomBytes(uint8_t *buffer, int n);

    void generateAESKey(uint8_t *buffer, uint16_t keySize);

    bool aesEncrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen,
                    const uint8_t *key, const uint8_t *iv, uint8_t *tag);

    bool aesDecrypt(uint8_t *out, int *outLen, const uint8_t *in, int inLen,
                    const uint8_t *key, const uint8_t *iv, uint8_t *tag);

    bool rsaEncrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen,
                    const char *rsaPublicKey);

    bool rsaDecrypt(uint8_t *out, size_t *outLen, const uint8_t *in, size_t inLen,
                    const char *rsaPublicKey);

    char *hashPassword(const char *password, size_t passwordLen);

    char *saltedHash(const char *password, size_t passwordLen, const char *salt,
                     size_t saltLen);

    uint16_t randomPort(uint16_t lowerBound, uint16_t upperBound);

#ifdef __cplusplus
}
#endif

#endif
