#ifndef HOMELINK_NET_H
#define HOMELINK_NET_H

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum FileRecvMode
    {
        e_Default = 0,
        e_ServerRecv = 1,
        e_ClientRecv = 2
    } FileRecvMode;

#include <stdbool.h>
#include <stdint.h>

    // Attempts to send the first n bytes in the buffer over TCP.
    extern bool sendBufferTcp(int sd, const uint8_t *buffer, int n);

    // Attempts to receive n bytes, writes to the buffer over TCP.
    extern bool recvBufferTcp(int sd, uint8_t *buffer, int n);

    // Sends a file encrypted with the given AES key, uses AES-GCM
    // encryption. Uses TCP.
    extern bool sendFile(int sd, const char *filePath, const char *filename,
                         const uint8_t *aesKey, int32_t fileTag);

    // Attempts to receive a file, prepends prefix to the file locations.
    // Decrypts with the given AES key, uses AES-GCM encryption. Returns
    // the file path on success, NULL on failure. Uses TCP.
    extern char *recvFile(int sd, const char *prefix, const uint8_t *aesKey,
                          FileRecvMode mode);

#ifdef __cplusplus
}
#endif

#endif
