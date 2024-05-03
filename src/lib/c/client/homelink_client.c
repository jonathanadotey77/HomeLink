#include <homelink_client.h>

#include <homelink_misc.h>
#include <homelink_net.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const int RETRY_COUNT = 5;

typedef struct HomeLinkClient
{
    char serverControlAddressStr[64];
    struct sockaddr_in6 serverAddress;
    uint16_t serverPort;
    char serverPublicKey[512];
    char clientPublicKey[512];
    uint8_t aesKey[32];
    char hostId[33];
    char serviceId[33];
    uint32_t connectionId;
    char sessionKey[256];
} HomeLinkClient;

const size_t HomeLinkClient__SIZE = sizeof(HomeLinkClient);

const char *getHostKey()
{
    static bool initialized = false;
    static char hostKey[128] = {0};
    if (!initialized)
    {
        char hostKeyFilePath[128] = {0};
        snprintf(hostKeyFilePath, sizeof(hostKeyFilePath) - 1, "%s/.config/homelink/host.key", getenv("HOME"));

        if (!fileExists(hostKeyFilePath))
        {
            char tempHostKey[128] = {0};
            FILE *fp = fopen(hostKeyFilePath, "w");
            if (fp == NULL)
            {
                fprintf(stderr, "fopen() failed\n");
                return NULL;
            }
            uint8_t key[32] = {0};
            randomBytes(key, sizeof(key));
            getByteStr(tempHostKey, key, sizeof(key));
            fprintf(fp, "%s", tempHostKey);
            fclose(fp);
            memset(key, 0, sizeof(key));
            memset(tempHostKey, 0, sizeof(tempHostKey));
        }

        FILE *fp = fopen(hostKeyFilePath, "r");
        if (fp == NULL)
        {
            fprintf(stderr, "fopen() failed\n");
            return NULL;
        }

        for (int i = 0; i < (int)sizeof(hostKey) - 1; ++i)
        {
            char c = fgetc(fp);
            if (c == EOF)
            {
                break;
            }

            hostKey[i] = c;
        }

        fclose(fp);
        initialized = true;
    }

    return hostKey;
}

static void HomeLinkClient__sendCommand(int sd, HomeLinkClient *client, const char *command)
{

    CommandPacket commandPacket;
    memset(&commandPacket, 0, sizeof(commandPacket));

    commandPacket.packetType = e_Command;
    commandPacket.connectionId = client->connectionId;

    size_t len = sizeof(commandPacket.sessionToken);
    rsaEncrypt(commandPacket.sessionToken, &len, (uint8_t *)client->sessionKey, strlen(client->sessionKey) + 1, client->serverPublicKey);

    char commandData[200] = {0};
    len = sizeof(commandPacket.data);
    randomBytes((uint8_t *)commandData, 32);
    strncpy(commandData + 32, command, sizeof(commandData) - 32 - 1);
    rsaEncrypt(commandPacket.data, &len, (uint8_t *)commandData, sizeof(commandData), client->serverPublicKey);

    uint8_t buffer[CommandPacket_SIZE];
    CommandPacket_serialize(buffer, &commandPacket);

    sendBufferTcp(sd, buffer, sizeof(buffer));
}

bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId, int argc, char **argv)
{
    if (getHostKey() == NULL)
    {
        return false;
    }

    if (!initializeSecurity())
    {
        return false;
    }

    memset(client, 0, sizeof(HomeLinkClient));
    client->serverPort = 0;

    for (int i = 0; i < argc; ++i)
    {
        char arg[128] = {0};
        strncpy(arg, argv[i], sizeof(arg) - 1);

        char *token = strtok(arg, "=");
        if (token == NULL)
        {
            continue;
        }

        if (stringEqual(token, "--host-id"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }
            strncpy(client->hostId, field, sizeof(client->hostId) - 1);
        }
        else if (stringEqual(token, "--server-address"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(client->serverControlAddressStr, field, sizeof(client->serverControlAddressStr));
        }
        else if (stringEqual(token, "--server-port"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            for (char *p = field; *p != '\0'; ++p)
            {
                if (!isdigit(*p))
                {
                    fprintf(stderr, "Invalid value for %s\n", token);
                    return false;
                }
            }

            int i = atoi(field);
            if (i == 0 || i >= UINT16_MAX)
            {
                fprintf(stderr, "Invalid value for %s\n", token);
                return false;
            }

            client->serverPort = (uint16_t)i;
        }
    }

    if (client->hostId[0] == 0)
    {
        fprintf(stderr, "--host-id is a required argument for client intialization\n");
        return false;
    }
    if (client->serverControlAddressStr[0] == 0)
    {
        fprintf(stderr, "--server-address is a required argument for client intialization\n");
        return false;
    }
    if (client->serverPort == 0)
    {
        fprintf(stderr, "--server-port is a required argument for client intialization\n");
        return false;
    }

    struct in6_addr serverIpAddress = parseIpAddress(client->serverControlAddressStr);
    client->serverAddress.sin6_family = AF_INET6;
    memcpy(&client->serverAddress.sin6_addr, &serverIpAddress, sizeof(client->serverAddress.sin6_addr));
    client->serverAddress.sin6_port = htons(client->serverPort);
    client->serverAddress.sin6_flowinfo = 0;
    client->serverAddress.sin6_scope_id = 0;

    strncpy(client->serviceId, serviceId, sizeof(client->serviceId));

    client->connectionId = 0;

    return true;
}

bool HomeLinkClient__fetchKeys(HomeLinkClient *client)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return e_RegisterFailed;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return e_RegisterFailed;
    }

    KeyRequestPacket keyRequestPacket;
    memset(&keyRequestPacket, 0, sizeof(keyRequestPacket));

    uint32_t connectionId = 0;

    size_t clientPublicKeyLen = 0;
    getRSAPublicKey(client->clientPublicKey, &clientPublicKeyLen);

    keyRequestPacket.packetType = e_KeyRequest;
    memcpy(keyRequestPacket.rsaPublicKey, client->clientPublicKey, sizeof(keyRequestPacket.rsaPublicKey));

    uint8_t buffer[1024] = {0};

    for (int i = 0; i < RETRY_COUNT; ++i)
    {
        randomBytes((uint8_t *)&connectionId, sizeof(connectionId));
        keyRequestPacket.connectionId = connectionId;
        KeyRequestPacket_serialize(buffer, &keyRequestPacket);

        bool status = sendBufferTcp(sd, buffer, 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            close(sd);
            return false;
        }

        status = sendBufferTcp(sd, buffer + 1, KeyRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            close(sd);
            return false;
        }

        memset(buffer, 0, sizeof(buffer));
        status = recvBufferTcp(sd, buffer, KeyResponsePacket_SIZE);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return false;
        }

        KeyResponsePacket keyResponsePacket;
        memset(&keyResponsePacket, 0, sizeof(keyResponsePacket));

        KeyResponsePacket_deserialize(&keyResponsePacket, buffer);

        strncpy(client->serverPublicKey, keyResponsePacket.rsaPublicKey, sizeof(keyResponsePacket.rsaPublicKey) - 1);

        uint8_t aesKey[256];
        size_t len = sizeof(aesKey);
        rsaDecrypt(aesKey, &len, keyResponsePacket.aesKey, sizeof(keyResponsePacket.aesKey), NULL);
        memcpy(client->aesKey, aesKey, 32);

        memset(aesKey, 0, sizeof(aesKey));
        if (keyResponsePacket.success == 0)
        {
            fprintf(stderr, "Key request failed\n");
            continue;
        }

        client->connectionId = connectionId;

        return true;
    }

    close(sd);

    return false;
}

RegisterStatus HomeLinkClient__registerHost(HomeLinkClient *client)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return e_RegisterFailed;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return e_RegisterFailed;
    }

    const char *hostKey = getHostKey();
    if (hostKey == NULL)
    {
        fprintf(stderr, "Failed to read host key\n");
        close(sd);
        return e_RegisterFailed;
    }

    RegisterRequestPacket registerRequestPacket;
    uint8_t buffer[1024];
    for (int i = 0; i < RETRY_COUNT; ++i)
    {
        memset(buffer, 0, sizeof(buffer));
        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
        registerRequestPacket.packetType = e_RegisterRequest;
        registerRequestPacket.registrationType = e_HostRegistration;
        strncpy(registerRequestPacket.hostId, client->hostId, sizeof(registerRequestPacket.hostId) - 1);
        uint8_t data[128] = {0};
        randomBytes(data, 32);
        strncpy((char *)(data + 32), hostKey, 65);
        memset(data + 104, 0, 24);
        size_t len = sizeof(registerRequestPacket.data);
        bool success = rsaEncrypt(registerRequestPacket.data, &len, data, sizeof(data), client->serverPublicKey);
        if (!success)
        {
            fprintf(stderr, "rsaEncrypt() failed\n");
            close(sd);
            return e_RegisterFailed;
        }

        memset(data, 0, sizeof(data));

        RegisterRequestPacket_serialize(buffer, &registerRequestPacket);
        bool status = sendBufferTcp(sd, buffer, 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            close(sd);
            return e_RegisterFailed;
        }

        status = sendBufferTcp(sd, buffer + 1, RegisterRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            close(sd);
            return e_RegisterFailed;
        }

        memset(buffer, 0, sizeof(buffer));
        status = recvBufferTcp(sd, buffer, RegisterResponsePacket_SIZE);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return e_RegisterFailed;
        }

        if (i + 1 == RETRY_COUNT)
        {
            close(sd);
            return e_RegisterFailed;
        }
    }
    close(sd);

    RegisterResponsePacket registerResponsePacket = {0};
    RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

    return registerResponsePacket.status;
}

RegisterStatus HomeLinkClient__registerService(HomeLinkClient *client, const char *serviceId, const char *password)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return e_RegisterFailed;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return e_RegisterFailed;
    }

    char *hashedPassword = hashPassword(password, strlen(password));
    uint8_t passwordData[192] = {0};

    const char *hostKey = getHostKey();
    if (hostKey == NULL)
    {
        fprintf(stderr, "Failed to read host key\n");
        close(sd);
        return e_RegisterFailed;
    }
    strncpy((char *)(passwordData) + 32, getHostKey(), 65);
    strncpy((char *)(passwordData) + 97, hashedPassword, 65);
    memset(hashedPassword, 0, strlen(hashedPassword));
    free(hashedPassword);

    passwordData[96] = '\0';
    passwordData[161] = '\0';
    uint8_t buffer[1024];

    for (int i = 0; i < RETRY_COUNT; ++i)
    {
        RegisterRequestPacket registerRequestPacket;
        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));

        randomBytes(passwordData, 32);

        strncpy(registerRequestPacket.hostId, client->hostId, sizeof(registerRequestPacket.hostId) - 1);
        strncpy(registerRequestPacket.serviceId, serviceId, sizeof(registerRequestPacket.serviceId) - 1);

        size_t len = sizeof(registerRequestPacket.data);
        rsaEncrypt(registerRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);

        registerRequestPacket.packetType = e_RegisterRequest;
        registerRequestPacket.registrationType = e_ServiceRegistration;

        memset(buffer, 0, sizeof(buffer));
        RegisterRequestPacket_serialize(buffer, &registerRequestPacket);

        bool status = sendBufferTcp(sd, buffer, 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return e_RegisterFailed;
        }

        status = sendBufferTcp(sd, buffer + 1, RegisterRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return e_RegisterFailed;
        }

        memset(buffer, 0, sizeof(buffer));

        status = recvBufferTcp(sd, buffer, RegisterResponsePacket_SIZE);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return e_RegisterFailed;
        }

        RegisterResponsePacket registerResponsePacket;
        RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

        memset(passwordData, 0, sizeof(passwordData));
        close(sd);
        if (registerResponsePacket.status == e_AlreadyExists || registerResponsePacket.status == e_RegisterSuccess)
        {
            return registerResponsePacket.status;
        }
        else
        {
            fprintf(stderr, "Register error\n");
            return e_RegisterFailed;
        }
    }

    memset(passwordData, 0, sizeof(passwordData));
    close(sd);
    return e_RegisterFailed;
}

bool HomeLinkClient__login(HomeLinkClient *client, const char *password)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return e_RegisterFailed;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return e_RegisterFailed;
    }

    uint8_t buffer[1024] = {0};

    char *hashedPassword = hashPassword(password, strlen(password));
    uint8_t passwordData[192] = {0};
    strncpy((char *)(passwordData) + 32, hashedPassword, strlen(hashedPassword));
    memset(hashedPassword, 0, strlen(hashedPassword));
    free(hashedPassword);

    for (int i = 0; i < RETRY_COUNT; ++i)
    {
        LoginRequestPacket loginRequestPacket;
        memset(&loginRequestPacket, 0, sizeof(loginRequestPacket));

        loginRequestPacket.packetType = e_LoginRequest;
        loginRequestPacket.connectionId = client->connectionId;
        strncpy(loginRequestPacket.hostId, client->hostId, sizeof(loginRequestPacket.hostId) - 1);
        strncpy(loginRequestPacket.serviceId, client->serviceId, sizeof(loginRequestPacket.serviceId) - 1);

        randomBytes(passwordData, 32);
        randomBytes(passwordData + 104, 24);

        size_t len = sizeof(loginRequestPacket.data);
        rsaEncrypt(loginRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);

        memset(buffer, 0, sizeof(buffer));

        LoginRequestPacket_serialize(buffer, &loginRequestPacket);

        bool status = sendBufferTcp(sd, buffer, 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return false;
        }

        status = sendBufferTcp(sd, buffer + 1, LoginRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return false;
        }

        status = recvBufferTcp(sd, buffer, LoginResponsePacket_SIZE);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return false;
        }

        LoginResponsePacket loginResponsePacket;
        LoginResponsePacket_deserialize(&loginResponsePacket, buffer);

        LoginStatus loginStatus = loginResponsePacket.status;

        if (loginStatus == e_LoginFailed)
        {
            fprintf(stderr, "Incorrect password\n");
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return false;
        }
        else if (loginStatus == e_LoginSuccess)
        {
            size_t len = sizeof(client->sessionKey);
            rsaDecrypt((uint8_t *)client->sessionKey, &len, loginResponsePacket.sessionKey, sizeof(loginResponsePacket.sessionKey), NULL);
            break;
        }
        else
        {
            fprintf(stderr, "Login error\n");
            memset(passwordData, 0, sizeof(passwordData));
            close(sd);
            return false;
        }
    }

    memset(passwordData, 0, sizeof(passwordData));
    close(sd);
    return true;
}

void HomeLinkClient__logout(HomeLinkClient *client)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return;
    }

    uint8_t buffer[1024] = {0};
    LogoutPacket logoutPacket;
    memset(&logoutPacket, 0, sizeof(logoutPacket));
    logoutPacket.packetType = e_Logout;
    logoutPacket.connectionId = client->connectionId;
    size_t len = sizeof(logoutPacket.sessionKey);
    bool status = rsaEncrypt(logoutPacket.sessionKey, &len, (uint8_t *)client->sessionKey, strlen(client->sessionKey) + 1, client->serverPublicKey);
    if (!status)
    {
        fprintf(stderr, "rsaEncrypt() failed\n");
        close(sd);
        return;
    }

    LogoutPacket_serialize(buffer, &logoutPacket);
    status = sendBufferTcp(sd, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        close(sd);
        return;
    }

    status = sendBufferTcp(sd, buffer + 1, LogoutPacket__SIZE - 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        close(sd);
        return;
    }

    close(sd);
}

char *HomeLinkClient__readFile(HomeLinkClient *client, const char *directory)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return NULL;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return NULL;
    }

    HomeLinkClient__sendCommand(sd, client, "READ_FILE");

    uint8_t buffer[1] = {0};
    bool status = recvBufferTcp(sd, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        close(sd);
        return NULL;
    }

    if (buffer[0] == 0)
    {
        // No file, return empty string
        return (char *)calloc(1, 1);
    }

    char *filePath = recvFile(sd, directory == NULL ? "" : directory, client->aesKey, e_ClientRecv);

    close(sd);
    sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed\n");
        exit(1);
    }

    return filePath;
}

bool HomeLinkClient__writeFile(HomeLinkClient *client, const char *destinationHostId, const char *destinationServiceId, const char *localPath, const char *remotePath)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return false;
    }

    char command[168] = {0};

    struct stat st;
    memset(&st, 0, sizeof(st));
    int rc = stat(localPath, &st);
    if (rc < 0)
    {
        close(sd);
        return false;
    }

    const uint64_t fileSize = st.st_size;

    snprintf(command, sizeof(command) - 1, "WRITE_FILE %s %s %s %llu", destinationHostId, destinationServiceId, remotePath, (unsigned long long)fileSize);

    if (connect(sd, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(sd);
        return false;
    }

    HomeLinkClient__sendCommand(sd, client, command);

    bool status = sendFile(sd, localPath, remotePath, client->aesKey);

    memset(&command, 0, sizeof(command));

    close(sd);

    return status;
}

void HomeLinkClient__destruct(HomeLinkClient *client)
{
    memset(client->sessionKey, 0, sizeof(client->sessionKey));
}
