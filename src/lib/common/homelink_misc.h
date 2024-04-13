#ifndef HOMELINK_MISC_H
#define HOMELINK_MISC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <netinet/in.h>

    struct in6_addr getIpAddress();

    int ipv4ToIpv6(const char *ipv4Str, char *ipv6Str);

    void getIpv6Str(char *out, const struct in6_addr *address);

    struct in6_addr parseIpAddress(const char *addressStr);

    void getByteStr(char *dest, const void *src, int n);

    void printBytes(const void *buffer, int n);

#ifdef __cplusplus
}
#endif

#endif