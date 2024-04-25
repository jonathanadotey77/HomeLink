#include <homelink_net.h>

#include <homelink_security.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define HOMELINK_FILE_BLOCK_SIZE 8192

static void makeParentDirectory(const char *dir)
{
    char temp[256];
    char *p = NULL;

    snprintf(temp, sizeof(temp), "%s", dir);
    int len = (int)strlen(temp);

    if (temp[len - 1] == '/')
    {
        temp[len - 1] = '\0';
    }

    for (int last = len - 2; last >= 0; --last)
    {
        if (temp[last] == '/')
        {
            temp[last] = '\0';
        }
    }

    for (p = temp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            mkdir(temp, 0777);
            *p = '/';
        }
    }
    mkdir(temp, 0777);
}

bool sendBufferTcp(int sd, const uint8_t *buffer, int n)
{
    int bytesSent = 0;

    for (int i = 0; i < 10 && bytesSent < n; ++i)
    {
        int rc = send(sd, buffer + bytesSent, n - bytesSent, 0);
        if (rc < 0)
        {
            fprintf(stderr, "send() failed [%d]\n", errno);
            return false;
        }

        bytesSent += rc;
    }

    return bytesSent == n;
}

bool recvBufferTcp(int sd, uint8_t *buffer, int n)
{
    int bytesReceived = 0;

    for (int i = 0; i < 10 && bytesReceived < n; ++i)
    {
        int rc = recv(sd, buffer + bytesReceived, n - bytesReceived, 0);
        if (rc < 0)
        {
            fprintf(stderr, "recv() failed [%d]\n", errno);
            return false;
        }

        bytesReceived += rc;
    }

    return bytesReceived == n;
}

bool sendFile(int sd, const char *filePath, const char *filename, const uint8_t *aesKey)
{
    uint8_t sendBuffer[HOMELINK_FILE_BLOCK_SIZE + 16] = {0};
    uint8_t recvBuffer[17] = {0};
    char fileInfo[129] = {0};

    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(filePath, &st) < 0)
    {
        fprintf(stderr, "stat() failed\n");
        return false;
    }

    const uint64_t fileSize = (uint64_t)st.st_size;

    snprintf(fileInfo, 128, "%s %llu", filename, (unsigned long long int)fileSize);

    // Send file info
    int len = sizeof(fileInfo) - 1;
    uint8_t *iv = sendBuffer + len;
    uint8_t *tag = iv + 16;
    randomBytes(iv, 16);
    bool status = aesEncrypt(sendBuffer, &len, (const uint8_t *)fileInfo, len, aesKey, iv, tag);
    if (!status)
    {
        fprintf(stderr, "Failed to encrypt file info\n");
        return false;
    }

    status = sendBufferTcp(sd, sendBuffer, sizeof(fileInfo) - 1 + 32);
    if (!status)
    {
        fprintf(stderr, "Could not send file info\n");
        return false;
    }

    // Receive first ACK
    status = recvBufferTcp(sd, recvBuffer, sizeof(recvBuffer));
    if (!status)
    {
        fprintf(stderr, "Coult not receive first ACK\n");
        return false;
    }
    iv = recvBuffer + 1;
    tag = sendBuffer + HOMELINK_FILE_BLOCK_SIZE;

    uint64_t bytesSent = 0;
    uint8_t data[HOMELINK_FILE_BLOCK_SIZE];

    FILE *fp = fopen(filePath, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "fopen() failed\n");
        return false;
    }

    memset(data, 0, sizeof(data));
    fread(data, 1, HOMELINK_FILE_BLOCK_SIZE, fp);

    while (bytesSent < fileSize)
    {
        // Encrypt bytes
        len = HOMELINK_FILE_BLOCK_SIZE;
        status = aesEncrypt(sendBuffer, &len, data, sizeof(data), aesKey, iv, tag);
        if (!status)
        {
            fprintf(stderr, "aesEncrypt() failed\n");
            status = false;
            break;
        }

        // Send bytes
        status = sendBufferTcp(sd, sendBuffer, sizeof(sendBuffer));
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            status = false;
            break;
        }

        // Receive ACK
        status = recvBufferTcp(sd, recvBuffer, sizeof(recvBuffer));
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            status = false;
            break;
        }

        // Read bytes if needed
        if (recvBuffer[0] == 0)
        {
            bytesSent += HOMELINK_FILE_BLOCK_SIZE;
            memset(data, 0, sizeof(data));
            fread(data, 1, HOMELINK_FILE_BLOCK_SIZE, fp);
        }
    }

    fclose(fp);

    memset(data, 0, sizeof(data));
    memset(sendBuffer, 0, sizeof(sendBuffer));
    memset(recvBuffer, 0, sizeof(recvBuffer));

    return status;
}

char *recvFile(int sd, const char *prefix, const uint8_t *aesKey, FileRecvMode mode)
{
    uint8_t sendBuffer[17] = {0};
    uint8_t *iv = sendBuffer + 1;
    uint8_t recvBuffer[HOMELINK_FILE_BLOCK_SIZE + 16] = {0};
    char fileInfo[129] = {0};
    bool status = true;

    // Receive file name and size
    status = recvBufferTcp(sd, recvBuffer, sizeof(fileInfo) - 1 + 32);
    if (!status)
    {
        fprintf(stderr, "Could not fetch file info\n");
        return NULL;
    }

    int len = sizeof(fileInfo) - 1;
    status = aesDecrypt((uint8_t *)fileInfo, &len, recvBuffer, len, aesKey, recvBuffer + sizeof(fileInfo) - 1, recvBuffer + sizeof(fileInfo) - 1 + 16);
    if (!status)
    {
        fprintf(stderr, "aesDecrypt() failed\n");
        return NULL;
    }

    // Parse filaneme and fileSize
    const char *filename = fileInfo;
    if (mode == e_ServerRecv)
    {
        for (uint32_t i = 0; i < sizeof(fileInfo); ++i)
        {
            if (fileInfo[i] == '/')
            {
                fileInfo[i] = '+';
            }
        }
    } else if(mode == e_ClientRecv) {
        for (uint32_t i = 0; i < sizeof(fileInfo); ++i)
        {
            if (fileInfo[i] == '+')
            {
                fileInfo[i] = '/';
            }
        }
    }

    uint64_t fileSize = 0;
    status = false;
    for (int i = 0; i < (int)sizeof(fileInfo) - 1 && fileInfo[i] != '\0'; ++i)
    {
        if (fileInfo[i] == ' ')
        {
            fileInfo[i] = '\0';
            fileSize = (uint64_t)atoll(fileInfo + i + 1);
            status = true;
            break;
        }
    }

    if (!status || strlen(filename) == 0)
    {
        fprintf(stderr, "Invalid file info\n");
        return NULL;
    }

    // Send the first ACK
    sendBuffer[0] = 0;
    randomBytes(iv, 16);

    status = sendBufferTcp(sd, sendBuffer, sizeof(sendBuffer));
    if (!status)
    {
        fprintf(stderr, "Could not send first ACK\n");
        return NULL;
    }

    char *filePath = (char *)calloc(256, 1);
    snprintf(filePath, 255, "%s%s", prefix, filename);

    makeParentDirectory(filePath);

    FILE *fp = fopen(filePath, "wb");
    if (!fp)
    {
        fprintf(stderr, "fopen() failed {%s}\n", filePath);
        free(filePath);
        return NULL;
    }

    uint64_t bytesReceived = 0;
    uint32_t blockNumber = 0;
    uint8_t data[HOMELINK_FILE_BLOCK_SIZE];
    while (bytesReceived < fileSize)
    {
        // Receive bytes
        status = recvBufferTcp(sd, recvBuffer, sizeof(recvBuffer));
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            break;
        }

        // Decrypt bytes
        uint8_t *tag = recvBuffer + HOMELINK_FILE_BLOCK_SIZE;
        int len = sizeof(data);
        memset(data, 0, sizeof(data));
        status = aesDecrypt(data, &len, recvBuffer, HOMELINK_FILE_BLOCK_SIZE, aesKey, iv, tag);
        if (status)
        {
            // Write to file
            sendBuffer[0] = 0;
            bytesReceived += HOMELINK_FILE_BLOCK_SIZE;

            uint64_t bytes = HOMELINK_FILE_BLOCK_SIZE;
            if (bytesReceived >= fileSize)
            {
                bytes = fileSize - blockNumber * HOMELINK_FILE_BLOCK_SIZE;
            }
            blockNumber += 1;

            fwrite(data, bytes, 1, fp);
        }
        else
        {
            sendBuffer[0] = 1;
        }

        // Send ACK
        randomBytes(iv, 16);
        status = sendBufferTcp(sd, sendBuffer, sizeof(sendBuffer));
    }

    fclose(fp);

    memset(fileInfo, 0, sizeof(fileInfo));
    memset(sendBuffer, 0, sizeof(sendBuffer));
    memset(recvBuffer, 0, sizeof(recvBuffer));

    if (bytesReceived < fileSize)
    {
        remove(filename);
        free(filePath);
        return NULL;
    }

    return filePath;
}
