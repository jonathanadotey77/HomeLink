#ifndef HOMELINK_MISC_H
#define HOMELINK_MISC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <netinet/in.h>
#include <stdbool.h>

    // Compares two strings.
    bool stringEqual(const char *s1, const char *s2);

    // Returns the local IP address.
    struct in6_addr getIpAddress();

    // Converts an IPv4 string to an IPv6 string.
    int ipv4ToIpv6(const char *ipv4Str, char *ipv6Str);

    // Writes the IPv6 IP address from the in6_addr struct to a buffer.
    void getIpv6Str(char *out, const struct in6_addr *address);

    // Returns an in6_addr struct that represents the given IP address.
    struct in6_addr parseIpAddress(const char *addressStr);

    // Returns the bytes in string form.
    void getByteStr(char *dest, const void *src, int n);

    // Prints the first n bytes in the buffer.
    void printBytes(const void *buffer, int n);

    // Checks if a file exists on disk at the given file path.
    bool fileExists(const char *filePath);

    // Gives a random port within the given range, inclusive.
    uint16_t randomPort(uint16_t lowerBound, uint16_t upperBound);

#ifdef __cplusplus
}
#endif

#endif
