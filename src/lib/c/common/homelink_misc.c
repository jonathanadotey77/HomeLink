#include <homelink_misc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static struct in6_addr localIpAddress;
static volatile bool foundIp = false;

bool stringEqual(const char *s1, const char *s2)
{
    if (strlen(s1) != strlen(s2))
    {
        return false;
    }

    return strcmp(s1, s2) == 0;
}

struct in6_addr getIpAddress()
{
    if (foundIp)
    {
        return localIpAddress;
    }
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;

    if (getifaddrs(&ifAddrStruct) == -1)
    {
        fprintf(stderr, "Failed to get interface addresses\n");
        return in6addr_any;
    }

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET6 && (ifa->ifa_flags & IFF_LOOPBACK) == 0)
        {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)(ifa->ifa_addr);
            if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr) && !IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr))
            {
                localIpAddress = addr->sin6_addr;
                freeifaddrs(ifAddrStruct);
                foundIp = true;
                return localIpAddress;
            }
        }
    }

    if (ifAddrStruct != NULL)
    {
        freeifaddrs(ifAddrStruct);
    }

    fprintf(stderr, "Failed to get public IPv6 address\n");
    return in6addr_any;
}

int ipv4ToIpv6(const char *ipv4Str, char *ipv6Str)
{
    struct in_addr ipv4Addr;
    struct in6_addr ipv6Addr;

    if (inet_pton(AF_INET, ipv4Str, &ipv4Addr) != 1)
    {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ipv4Str);
        return -1;
    }

    if (inet_pton(AF_INET6, "::ffff:0:0", &ipv6Addr) != 1)
    {
        perror("inet_pton");
        return -1;
    }

    memcpy(&ipv6Addr.s6_addr[12], &ipv4Addr.s_addr, sizeof(ipv4Addr.s_addr));

    if (inet_ntop(AF_INET6, &ipv6Addr, ipv6Str, INET6_ADDRSTRLEN) == NULL)
    {
        perror("inet_ntop");
        return -1;
    }

    return 0;
}

void getIpv6Str(char *out, const struct in6_addr *address)
{
    sprintf(out, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)address->s6_addr[0], (int)address->s6_addr[1],
            (int)address->s6_addr[2], (int)address->s6_addr[3],
            (int)address->s6_addr[4], (int)address->s6_addr[5],
            (int)address->s6_addr[6], (int)address->s6_addr[7],
            (int)address->s6_addr[8], (int)address->s6_addr[9],
            (int)address->s6_addr[10], (int)address->s6_addr[11],
            (int)address->s6_addr[12], (int)address->s6_addr[13],
            (int)address->s6_addr[14], (int)address->s6_addr[15]);
}

struct in6_addr parseIpAddress(const char *addressStr)
{
    struct in6_addr address;
    memset(&address, 0, sizeof(address));
    char formatted[128];
    memset(formatted, 0, sizeof(formatted));

    int t = 0;

    for (const char *p = addressStr; *p != '\0'; ++p)
    {
        if (*p == '.')
        {
            t = 1;
            break;
        }
        else if (*p == ':')
        {
            t = 2;
            break;
        }
    }

    if (!t)
    {
        fprintf(stderr, "Could not parse address\n");
        return address;
    }

    if (t == 1)
    {
        ipv4ToIpv6(addressStr, formatted);
    }

    inet_pton(AF_INET6, formatted, &address);

    return address;
}

void getByteStr(char *dest, const void *src, int n)
{
    const char *hex = "0123456789abcdef";
    char *pout = dest;
    const uint8_t *ptr = (const uint8_t *)(src);
    int i = 0;
    for (; i < n - 1; ++i)
    {
        *pout++ = hex[(*ptr >> 4) & 0xF];
        *pout++ = hex[(*ptr++) & 0xF];
    }
    *pout++ = hex[(*ptr >> 4) & 0xF];
    *pout++ = hex[(*ptr) & 0xF];
    *pout = 0;
}

void printBytes(const void *buffer, int n)
{
    char *temp = malloc(n << 2);

    getByteStr(temp, buffer, n);
    printf("%s\n", temp);

    free(temp);
}

bool fileExists(const char *filePath)
{
    struct stat buffer;
    return (stat(filePath, &buffer) == 0);
}

uint16_t randomPort(uint16_t lowerBound, uint16_t upperBound)
{
    static bool randInitialized = false;

    if (!randInitialized)
    {
        srand(time(NULL));
        randInitialized = true;
    }

    uint32_t range = (uint32_t)upperBound - (uint32_t)lowerBound + 1;
    uint32_t idx = (uint32_t)rand() % range;
    return lowerBound + (uint16_t)idx;
}
