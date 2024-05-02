#ifndef HOMELINK_CLIENT_H
#define HOMELINK_CLIENT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <homelink_packet.h>

#include <arpa/inet.h>
#include <stdbool.h>

    extern const size_t HomeLinkClient__SIZE;

    typedef struct HomeLinkClient HomeLinkClient;

    const char *getHostKey();

    bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId,
                                    int argc, char **argv);

    bool HomeLinkClient__fetchKeys(HomeLinkClient *client);

    RegisterStatus HomeLinkClient__registerHost(HomeLinkClient *client);

    RegisterStatus HomeLinkClient__registerService(HomeLinkClient *client, const char *serviceId, const char *password);

    bool HomeLinkClient__login(HomeLinkClient *client, const char *password);

    void HomeLinkClient__logout(HomeLinkClient *client);

    char *HomeLinkClient__readFile(HomeLinkClient *client, const char *directory);

    bool HomeLinkClient__writeFile(HomeLinkClient *client,
                                   const char *destinationHostId,
                                   const char *destinationServiceId,
                                   const char *localPath, const char *remotePath);

    void HomeLinkClient__destruct(HomeLinkClient *client);

#ifdef __cplusplus
}
#endif

#endif
