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

    bool sendBufferTcp(int sd, const uint8_t *buffer, int n);

    bool recvBufferTcp(int sd, uint8_t *buffer, int n);

    bool sendFile(int sd, const char *filePath, const char *filename, const uint8_t *aesKey);

    char *recvFile(int sd, const char *prefix, const uint8_t *aesKey, FileRecvMode mode);

#ifdef __cplusplus
}
#endif

#endif