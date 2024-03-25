#ifndef HOMELINK_SECURITY
#define HOMELINK_SECURITY

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

    // uint16_t randomInt16();

    // uint32_t randomInt32();

    void randomBytes(uint8_t *buffer, int n);

    // void hashString(const char* unhashed, char* hashed);

    // bool validPassword(const char* password, unsigned long n);

    // ssize_t secureSendTo(int sockFd, const void* buffer, uint32_t n, const struct sockaddr_in6 *address, int* error);

    // ssize_t secureRecvFrom(int sockFd, void* buffer, const struct sockaddr_in6 *address, int* error);

#ifdef __cplusplus
}
#endif

#endif