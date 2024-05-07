#ifndef HOMELINK_CLIENT_H
#define HOMELINK_CLIENT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <arpa/inet.h>
#include <stdbool.h>

    extern const size_t HomeLinkClient_SIZE;

    typedef struct HomeLinkClient HomeLinkClient;

    typedef void (*HomeLinkAsyncReadFileCallback)(const char *, void *);

    // Returns pointer to the host key that is read
    // from the host key file, the file is read once.
    const char *getHostKey();

    // Creates client struct, allocated on the heap.
    HomeLinkClient *HomeLinkClient__create(const char *hostId, const char *serviceId, const char *serverAddress, int port);

    // Creates and returns new heap-allocated HomeLinkClient struct.
    // Sets fields within the struct using the provided args.
    HomeLinkClient *HomeLinkClient__createWithArgs(const char *serviceId, int argc, const char **argv);

    // Fetches the RSA public key and AES-256 key from the server,
    // while sending the client's RSA public key. All
    // HomeLinkClient functions except initialize require
    // the keys to be fetched.
    bool HomeLinkClient__fetchKeys(HomeLinkClient *client);

    // Registers the host with the server, may create host file if it
    // does not exist.
    int HomeLinkClient__registerHost(const HomeLinkClient *client);

    // Registers the service with the server, requires host key file
    // to already exist.
    int HomeLinkClient__registerService(const HomeLinkClient *client, const char *serviceId, const char *password);

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

    // Writes over session key and closes sockets, DOES NOT
    // free client memory.
    void HomeLinkClient__destruct(HomeLinkClient *client);

#ifdef __cplusplus
}
#endif

#endif
