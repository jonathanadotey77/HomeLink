#ifndef HOMELINK_CLIENT_H
#define HOMELINK_CLIENT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <arpa/inet.h>
#include <stdbool.h>

    typedef struct HomeLinkClient
    {
        int controlSocket;
        int dataSocket;
        char serverAddressStr[64];
        struct sockaddr_in6 serverAddress;
        struct sockaddr_in6 controlAddress;
        struct sockaddr_in6 dataAddress;
        uint16_t serverPort;
        char serverPublicKey[512];
        char clientPublicKey[512];
        char hostId[33];
        char serviceId[33];
        uint32_t connectionId;
    } HomeLinkClient;

    bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId);

    bool HomeLinkClient__login(HomeLinkClient *client, const char *password);

#ifdef __cplusplus
}
#endif

#endif