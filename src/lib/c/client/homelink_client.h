#ifndef HOMELINK_CLIENT_H
#define HOMELINK_CLIENT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <homelink_packet.h>

#include <arpa/inet.h>
#include <stdbool.h>

    extern const size_t HomeLinkClient_SIZE;

    typedef struct HomeLinkClient HomeLinkClient;

    typedef void (*HomeLinkAsyncReadFileCallback)(const char *, void *);

    // Returns pointer to the host key that is read
    // from the host key file, the file is read once.
    const char *getHostKey();

    // Sets fields within the HomeLinkClient struct using args.
    bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId,
                                    int argc, char **argv);

    // Fetches the RSA public key and AES-256 key from the server,
    // while sending the client's RSA public key. All
    // HomeLinkClient functions except initialize require
    // the keys to be fetched.
    bool HomeLinkClient__fetchKeys(HomeLinkClient *client);

    // Registers the host with the server, may create host file if it
    // does not exist.
    RegisterStatus HomeLinkClient__registerHost(const HomeLinkClient *client);

    // Registers the service with the server, requires host key file
    // to already exist.
    RegisterStatus HomeLinkClient__registerService(const HomeLinkClient *client, const char *serviceId, const char *password);

    // Tries login, initializes session key on success
    bool HomeLinkClient__login(HomeLinkClient *client, const char *password);

    // Uses session key to logout
    void HomeLinkClient__logout(HomeLinkClient *client);

    // Initiates async file reading. For correct functioning, only one
    // instance should be listening for a particular HostId and ServiceId.
    bool HomeLinkClient__readFileAsync(HomeLinkClient *client, const char *directory, HomeLinkAsyncReadFileCallback callback, void *context);

    // Waits for all async reading to stop.
    void HomeLinkClient__waitAsync(HomeLinkClient *client);

    // Stops all async reading.
    void HomeLinkClient__stopAsync(HomeLinkClient *client);

    // Checks for file in the service's queue, returns the path to the
    // stored file if a file is received, and empty string if the queue is
    // empty, and NULL on error.
    char *HomeLinkClient__readFile(const HomeLinkClient *client, const char *directory);

    // Adds a file to the destination's queue
    bool HomeLinkClient__writeFile(const HomeLinkClient *client,
                                   const char *destinationHostId,
                                   const char *destinationServiceId,
                                   const char *localPath, const char *remotePath);

    // Writes over session key
    void HomeLinkClient__destruct(HomeLinkClient *client);

#ifdef __cplusplus
}
#endif

#endif
