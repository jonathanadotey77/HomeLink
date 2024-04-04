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

    void getRSAPublicKey(char **buffer, size_t *len);

    void printRSAPublicKey();

    void randomBytes(uint8_t *buffer, int n);

    bool rsaEncrypt(uint8_t* out, size_t* outLen,  const uint8_t* in, size_t inLen, const char* rsaPemKey);

    bool rsaDecrypt(uint8_t* out, size_t* outLen,  const uint8_t* in, size_t inLen);

    // void hashString(const char* unhashed, char* hashed);

    // bool validPassword(const char* password, unsigned long n);

    // TCP
    ssize_t secureSend(int sockFd, const void* buffer, uint32_t n, const struct sockaddr_in6 *address, int* error);

    ssize_t secureRecv(int sockFd, void* buffer, uint32_t n, const struct sockaddr_in6 *expectedAddress, struct sockaddr_in6* fromAddress, int* error);

#ifdef __cplusplus
}
#endif  

#endif