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

    // Returns pointer to the host key that is read
    // from the host key file, the file is read once.
    const char *getHostKey();

    // Sets fields within the HomeLinkClient struct using args.
    bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId,
                                    int argc, char **argv);

    // Fetches the RSA public key and AES-256 key from the server,
    // while sending the client's RSA public key.
    bool HomeLinkClient__fetchKeys(HomeLinkClient *client);

    // Registers the host with the server using the
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
