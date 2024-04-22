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
        char serverControlAddressStr[64];
        struct sockaddr_in6 serverControlAddress;
        struct sockaddr_in6 serverDataAddress;
        struct sockaddr_in6 clientControlAddress;
        struct sockaddr_in6 clientDataAddress;
        uint16_t serverControlPort;
        uint16_t serverDataPort;
        char serverPublicKey[512];
        char clientPublicKey[512];
        uint8_t aesKey[32];
        char hostId[33];
        char serviceId[33];
        uint32_t connectionId;
        char sessionKey[256];
    } HomeLinkClient;

    bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId);

    bool HomeLinkClient__login(HomeLinkClient *client, const char *password);

    void HomeLinkClient__logout(HomeLinkClient *client);

    char* HomeLinkClient__readFile(HomeLinkClient* client, const char* directory);

    bool HomeLinkClient__writeFile(HomeLinkClient* client, const char* destinationHostId, const char* destinationServiceId, const char* localPath, const char* remotePath);

#ifdef __cplusplus
}
#endif

#endif
