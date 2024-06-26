#include <homelink_client.h>

#include <homelink_misc.h>
#include <homelink_net.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/evp.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct HomeLinkClient
{
    char serverAddressStr[64];
    struct sockaddr_in6 serverAddress;
    uint16_t serverPort;
    char serverPublicKey[512];
    char clientPublicKey[512];
    EVP_PKEY *keypair;
    uint8_t aesKey[32];
    char hostId[33];
    char serviceId[33];
    uint32_t connectionId;
    char sessionKey[48];
    volatile bool active;
    int syncSocket;
    int asyncFileSocket;
    pthread_t asyncFileThreadId;
} HomeLinkClient;

const size_t HomeLinkClient_SIZE = sizeof(HomeLinkClient);

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

typedef struct HomeLinkReadFileAsyncArgs
{
    const HomeLinkClient *client;
    const char *directory;
    HomeLinkAsyncReadFileCallback callback;
    void *context;
} HomeLinkReadFileAsyncArgs;

static void *HomeLinkClient__readFileAsyncThread(void *a)
{
    HomeLinkReadFileAsyncArgs *args = (HomeLinkReadFileAsyncArgs *)a;
    const HomeLinkClient *client = args->client;
    const char *directory = args->directory;
    HomeLinkAsyncReadFileCallback callback = args->callback;
    void *context = args->context;
    free(args);

    struct pollfd fds[1];
    char *filePath = NULL;

    AsyncListenRequestPacket asyncListenRequestPacket;
    asyncListenRequestPacket.packetType = e_AsyncListenRequest;
    asyncListenRequestPacket.eventType = e_FileEvent;
    asyncListenRequestPacket.connectionId = client->connectionId;
    bool status = encryptSessionKey(asyncListenRequestPacket.sessionKey, client->sessionKey, client->aesKey);
    if (!status)
    {
        fprintf(stderr, "encryptSessionKey() failed\n");
        return NULL;
    }

    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    AsyncListenRequestPacket_serialize(buffer, &asyncListenRequestPacket);

    status = sendBufferTcp(client->asyncFileSocket, buffer, AsyncListenRequestPacket_SIZE);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        memset(&asyncListenRequestPacket, 0, sizeof(asyncListenRequestPacket));
        return NULL;
    }

    while (client->active)
    {
        filePath = HomeLinkClient__readFile(client, directory);
        if (filePath == NULL)
        {
            fprintf(stderr, "Error with readFile\n");
            return NULL;
        }

        if (filePath[0] == '\0')
        {
            free(filePath);
            break;
        }

        callback(filePath, context);
        free(filePath);
        filePath = NULL;
    }

    while (client->active)
    {
        buffer[0] = 0;

        fds[0].events = POLLIN;
        fds[0].fd = client->asyncFileSocket;
        fds[0].revents = 0;

        int rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            break;
        }
        else if (rc == 0)
        {
            continue;
        }

        status = recvBufferTcp(client->asyncFileSocket, buffer, AsyncNotificationPacket_SIZE);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            break;
        }

        AsyncNotificationPacket asyncNotificationPacket;
        AsyncNotificationPacket_deserialize(&asyncNotificationPacket, buffer);

        filePath = NULL;
        AsyncEventType eventType = asyncNotificationPacket.eventType;
        int32_t expectedTag = asyncNotificationPacket.tag;

        if (eventType == e_FileEvent)
        {
            while (client->active)
            {
                filePath = HomeLinkClient__readFile(client, directory);
                if (filePath != NULL)
                {
                    if (filePath[0] != '\0')
                    {
                        if (callback != NULL)
                        {
                            callback(filePath, context);
                        }

                        int32_t tag = atoll(filePath + 256);
                        if (tag == expectedTag)
                        {
                            printf("Tag: %d\n", (int)tag);
                            break;
                        }
                    }
                    else
                    {
                        free(filePath);
                        break;
                    }
                }
                else
                {
                    fprintf(stderr, "Error with async readFile\n");
                    break;
                }

                if (filePath != NULL)
                {
                    free(filePath);
                }
            }
        }
    }

    return NULL;
}

static void HomeLinkClient__sendCommand(int sd, const HomeLinkClient *client, const char *command)
{
    CommandPacket commandPacket = {0};

    commandPacket.packetType = e_Command;
    commandPacket.connectionId = client->connectionId;

    encryptSessionKey(commandPacket.sessionKey, client->sessionKey, client->aesKey);

    char commandData[224] = {0};
    int len = sizeof(commandPacket.data);
    randomBytes((uint8_t *)commandData, 32);
    strncpy(commandData + 32, command, sizeof(commandData) - 32 - 1);

    uint8_t *iv = commandPacket.data + 224;
    uint8_t *tag = commandPacket.data + 240;

    randomBytes(iv, 16);
    aesEncrypt(commandPacket.data, &len, (uint8_t *)commandData, sizeof(commandData), client->aesKey, iv, tag);

    uint8_t buffer[CommandPacket_SIZE];
    CommandPacket_serialize(buffer, &commandPacket);

    sendBufferTcp(sd, buffer, sizeof(buffer));
}

HomeLinkClient *HomeLinkClient__create(const char *hostId, const char *serviceId, const char *serverAddress, int port)
{
    if (port <= 0 || port > UINT16_MAX)
    {
        fprintf(stderr, "Invalid port in HomeLinkClient__create()\n");
        return NULL;
    }
    if (getHostKey() == NULL)
    {
        return NULL;
    }

    HomeLinkClient *client = (HomeLinkClient *)calloc(1, sizeof(HomeLinkClient));
    if (client == NULL)
    {
        fprintf(stderr, "calloc() failed\n");
        return NULL;
    }

    if (!generateRSAKeys(&client->keypair))
    {
        return NULL;
    }

    strncpy(client->hostId, hostId, sizeof(client->hostId) - 1);
    strncpy(client->serviceId, serviceId, sizeof(client->serviceId) - 1);
    strncpy(client->serverAddressStr, serverAddress, sizeof(client->serverAddressStr) - 1);

    client->serverPort = (uint16_t)port;

    const struct in6_addr serverIpAddress = parseIpAddress(client->serverAddressStr);
    client->serverAddress.sin6_family = AF_INET6;
    memcpy(&client->serverAddress.sin6_addr, &serverIpAddress, sizeof(client->serverAddress.sin6_addr));
    client->serverAddress.sin6_port = htons(client->serverPort);
    client->serverAddress.sin6_flowinfo = 0;
    client->serverAddress.sin6_scope_id = 0;

    client->syncSocket = -1;
    client->asyncFileSocket = -1;

    client->active = true;

    return client;
}

HomeLinkClient *HomeLinkClient__createWithArgs(const char *serviceId, int argc, const char **argv)
{
    if (getHostKey() == NULL)
    {
        return NULL;
    }

    HomeLinkClient *client = (HomeLinkClient *)calloc(1, sizeof(HomeLinkClient));
    if (client == NULL)
    {
        fprintf(stderr, "calloc() failed\n");
        return NULL;
    }

    if (!generateRSAKeys(&client->keypair))
    {
        free(client);
        return NULL;
    }

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
                EVP_PKEY_free(client->keypair);
                free(client);
                return NULL;
            }
            strncpy(client->hostId, field, sizeof(client->hostId) - 1);
        }
        else if (stringEqual(token, "--server-address"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                EVP_PKEY_free(client->keypair);
                free(client);
                return NULL;
            }

            strncpy(client->serverAddressStr, field, sizeof(client->serverAddressStr));
        }
        else if (stringEqual(token, "--server-port"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                EVP_PKEY_free(client->keypair);
                free(client);
                return NULL;
            }

            for (char *p = field; *p != '\0'; ++p)
            {
                if (!isdigit(*p))
                {
                    fprintf(stderr, "Invalid value for %s\n", token);
                    EVP_PKEY_free(client->keypair);
                    free(client);
                    return NULL;
                }
            }

            int i = atoi(field);
            if (i == 0 || i >= UINT16_MAX)
            {
                fprintf(stderr, "Invalid value for %s\n", token);
                EVP_PKEY_free(client->keypair);
                free(client);
                return NULL;
            }

            client->serverPort = (uint16_t)i;
        }
    }

    if (client->hostId[0] == 0)
    {
        fprintf(stderr, "--host-id is a required argument for client intialization\n");
        EVP_PKEY_free(client->keypair);
        free(client);
        return NULL;
    }
    if (client->serverAddressStr[0] == 0)
    {
        fprintf(stderr, "--server-address is a required argument for client intialization\n");
        EVP_PKEY_free(client->keypair);
        free(client);
        return NULL;
    }
    if (client->serverPort == 0)
    {
        fprintf(stderr, "--server-port is a required argument for client intialization\n");
        EVP_PKEY_free(client->keypair);
        free(client);
        return NULL;
    }

    struct in6_addr serverIpAddress = parseIpAddress(client->serverAddressStr);
    client->serverAddress.sin6_family = AF_INET6;
    memcpy(&client->serverAddress.sin6_addr, &serverIpAddress, sizeof(client->serverAddress.sin6_addr));
    client->serverAddress.sin6_port = htons(client->serverPort);
    client->serverAddress.sin6_flowinfo = 0;
    client->serverAddress.sin6_scope_id = 0;

    strncpy(client->serviceId, serviceId, sizeof(client->serviceId));

    client->connectionId = 0;

    client->asyncFileThreadId = 0;

    client->syncSocket = -1;
    client->asyncFileSocket = -1;

    client->active = true;

    return client;
}

bool HomeLinkClient__connect(HomeLinkClient *client)
{
    client->syncSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client->syncSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return false;
    }

    if (connect(client->syncSocket, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(client->syncSocket);
        return false;
    }

    ConnectionRequestPacket connectionRequestPacket;
    memset(&connectionRequestPacket, 0, sizeof(connectionRequestPacket));

    uint32_t connectionId = 0;

    size_t clientPublicKeyLen = 0;
    getRSAPublicKey(client->keypair, client->clientPublicKey, &clientPublicKeyLen);

    connectionRequestPacket.packetType = e_ConnectionRequest;
    memcpy(connectionRequestPacket.rsaPublicKey, client->clientPublicKey, sizeof(connectionRequestPacket.rsaPublicKey));

    uint8_t buffer[1024] = {0};

    randomBytes((uint8_t *)&connectionId, sizeof(connectionId));
    connectionRequestPacket.connectionId = connectionId;
    ConnectionRequestPacket_serialize(buffer, &connectionRequestPacket);

    bool status = sendBufferTcp(client->syncSocket, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        return false;
    }

    status = sendBufferTcp(client->syncSocket, buffer + 1, ConnectionRequestPacket_SIZE - 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        return false;
    }

    memset(buffer, 0, sizeof(buffer));
    status = recvBufferTcp(client->syncSocket, buffer, ConnectionResponsePacket_SIZE);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        return false;
    }

    ConnectionResponsePacket connectionResponsePacket;
    memset(&connectionResponsePacket, 0, sizeof(connectionResponsePacket));

    ConnectionResponsePacket_deserialize(&connectionResponsePacket, buffer);

    strncpy(client->serverPublicKey, connectionResponsePacket.rsaPublicKey, sizeof(connectionResponsePacket.rsaPublicKey) - 1);

    uint8_t aesKey[256];
    size_t len = sizeof(aesKey);
    rsaDecrypt(aesKey, &len, connectionResponsePacket.aesKey, sizeof(connectionResponsePacket.aesKey), client->keypair);
    memcpy(client->aesKey, aesKey, 32);

    memset(aesKey, 0, sizeof(aesKey));
    if (connectionResponsePacket.success == 0)
    {
        fprintf(stderr, "Connection request failed\n");
        close(client->syncSocket);
    }

    client->connectionId = connectionId;

    return true;
}

int HomeLinkClient__registerHost(const HomeLinkClient *client)
{
    const char *hostKey = getHostKey();
    if (hostKey == NULL)
    {
        fprintf(stderr, "Failed to read host key\n");
        return e_RegisterFailed;
    }

    RegisterRequestPacket registerRequestPacket;
    uint8_t buffer[1024];
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
        return e_RegisterFailed;
    }

    memset(data, 0, sizeof(data));

    RegisterRequestPacket_serialize(buffer, &registerRequestPacket);
    bool status = sendBufferTcp(client->syncSocket, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        return e_RegisterFailed;
    }

    status = sendBufferTcp(client->syncSocket, buffer + 1, RegisterRequestPacket_SIZE - 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        return e_RegisterFailed;
    }

    memset(buffer, 0, sizeof(buffer));
    status = recvBufferTcp(client->syncSocket, buffer, RegisterResponsePacket_SIZE);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        return e_RegisterFailed;
    }

    RegisterResponsePacket registerResponsePacket = {0};
    RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

    return registerResponsePacket.status;
}

int HomeLinkClient__registerService(const HomeLinkClient *client, const char *serviceId, const char *password)
{
    if (strlen(serviceId) > 32)
    {
        fprintf(stderr, "ServiceId must be at most 32 characters\n");
        return e_RegisterFailed;
    }

    char *hashedPassword = hashPassword(password, strlen(password));
    uint8_t passwordData[192] = {0};

    const char *hostKey = getHostKey();
    if (hostKey == NULL)
    {
        fprintf(stderr, "Failed to read host key\n");
        return e_RegisterFailed;
    }
    strncpy((char *)(passwordData + 32), getHostKey(), 65);
    strncpy((char *)(passwordData + 97), hashedPassword, 65);
    memset(hashedPassword, 0, strlen(hashedPassword));
    free(hashedPassword);

    passwordData[96] = '\0';
    passwordData[161] = '\0';
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));

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

    bool status = sendBufferTcp(client->syncSocket, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed [%d]\n", errno);
        memset(passwordData, 0, sizeof(passwordData));
        return e_RegisterFailed;
    }

    status = sendBufferTcp(client->syncSocket, buffer + 1, RegisterRequestPacket_SIZE - 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed [%d]\n", errno);
        memset(passwordData, 0, sizeof(passwordData));
        return e_RegisterFailed;
    }

    memset(buffer, 0, sizeof(buffer));

    status = recvBufferTcp(client->syncSocket, buffer, RegisterResponsePacket_SIZE);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        memset(passwordData, 0, sizeof(passwordData));
        return e_RegisterFailed;
    }

    RegisterResponsePacket registerResponsePacket;
    RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

    memset(passwordData, 0, sizeof(passwordData));
    if (registerResponsePacket.status == e_AlreadyExists || registerResponsePacket.status == e_RegisterSuccess)
    {
        memcpy((void *)client->serviceId, serviceId, 32);
        return registerResponsePacket.status;
    }
    else
    {
        fprintf(stderr, "Register error\n");
        return e_RegisterFailed;
    }

    memset(passwordData, 0, sizeof(passwordData));
    return e_RegisterFailed;
}

int HomeLinkClient__login(HomeLinkClient *client, const char *password)
{
    uint8_t buffer[1024] = {0};

    const char *hostKey = getHostKey();
    if (hostKey == NULL)
    {
        return e_LoginFailed;
    }

    uint8_t passwordData[192] = {0};

    randomBytes(passwordData, 32);
    strncpy((char *)(passwordData + 32), hostKey, 65);

    char *hashedPassword = hashPassword(password, strlen(password));
    strncpy((char *)(passwordData + 97), hashedPassword, strlen(hashedPassword));
    memset(hashedPassword, 0, strlen(hashedPassword));
    free(hashedPassword);

    LoginRequestPacket loginRequestPacket;
    memset(&loginRequestPacket, 0, sizeof(loginRequestPacket));

    loginRequestPacket.packetType = e_LoginRequest;
    loginRequestPacket.connectionId = client->connectionId;
    strncpy(loginRequestPacket.hostId, client->hostId, sizeof(loginRequestPacket.hostId) - 1);
    strncpy(loginRequestPacket.serviceId, client->serviceId, sizeof(loginRequestPacket.serviceId) - 1);

    size_t len = sizeof(loginRequestPacket.data);
    bool status = rsaEncrypt(loginRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);
    if (!status)
    {
        fprintf(stderr, "rsaEcrypt() failed\n");
        return e_LoginFailed;
    }

    memset(buffer, 0, sizeof(buffer));

    LoginRequestPacket_serialize(buffer, &loginRequestPacket);

    status = sendBufferTcp(client->syncSocket, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        memset(passwordData, 0, sizeof(passwordData));
        return e_LoginFailed;
    }

    status = sendBufferTcp(client->syncSocket, buffer + 1, LoginRequestPacket_SIZE - 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        memset(passwordData, 0, sizeof(passwordData));
        return e_LoginFailed;
    }

    status = recvBufferTcp(client->syncSocket, buffer, LoginResponsePacket_SIZE);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        return e_LoginFailed;
    }

    LoginResponsePacket loginResponsePacket;
    LoginResponsePacket_deserialize(&loginResponsePacket, buffer);

    LoginStatus loginStatus = loginResponsePacket.status;

    if (loginStatus == e_LoginFailed)
    {
        fprintf(stderr, "Incorrect password\n");
        memset(passwordData, 0, sizeof(passwordData));
        return e_LoginFailed;
    }
    else if (loginStatus == e_LoginSuccess)
    {
        decryptSessionKey(client->sessionKey, loginResponsePacket.sessionKey, client->aesKey);
        return e_LoginSuccess;
    }
    else
    {
        fprintf(stderr, "Login error\n");
        memset(passwordData, 0, sizeof(passwordData));
        return e_LoginFailed;
    }

    memset(passwordData, 0, sizeof(passwordData));
    client->active = true;
    return e_LoginSuccess;
}

void HomeLinkClient__logout(HomeLinkClient *client)
{
    uint8_t buffer[1024] = {0};
    LogoutPacket logoutPacket;
    memset(&logoutPacket, 0, sizeof(logoutPacket));
    logoutPacket.packetType = e_Logout;
    logoutPacket.connectionId = client->connectionId;
    size_t len = sizeof(logoutPacket.data);
    bool status = rsaEncrypt(logoutPacket.data, &len, client->aesKey, sizeof(client->aesKey), client->serverPublicKey);
    if (!status)
    {
        fprintf(stderr, "rsaEncrypt() failed\n");
        return;
    }

    LogoutPacket_serialize(buffer, &logoutPacket);
    status = sendBufferTcp(client->syncSocket, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        return;
    }

    status = sendBufferTcp(client->syncSocket, buffer + 1, LogoutPacket_SIZE - 1);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
        return;
    }

    client->active = false;
}

bool HomeLinkClient__readFileAsync(HomeLinkClient *client, const char *directory, HomeLinkAsyncReadFileCallback callback, void *context)
{
    if (client->asyncFileThreadId != 0)
    {
        return false;
    }

    client->asyncFileSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client->asyncFileSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        EVP_PKEY_free(client->keypair);
        free(client);
        return NULL;
    }

    if (connect(client->asyncFileSocket, (const struct sockaddr *)(&client->serverAddress), (socklen_t)(sizeof(client->serverAddress))) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
        close(client->asyncFileSocket);
        client->asyncFileSocket = -1;
        return false;
    }

    HomeLinkReadFileAsyncArgs *args = (HomeLinkReadFileAsyncArgs *)calloc(1, sizeof(HomeLinkReadFileAsyncArgs));
    args->client = client;
    args->directory = directory;
    args->callback = callback;
    args->context = context;

    pthread_create(&client->asyncFileThreadId, NULL, HomeLinkClient__readFileAsyncThread, (void *)args);

    return true;
}

void HomeLinkClient__waitAsync(HomeLinkClient *client)
{
    if (client->asyncFileThreadId != 0)
    {
        pthread_join(client->asyncFileThreadId, NULL);
        client->asyncFileThreadId = 0;
    }
}

void HomeLinkClient__stopAsync(HomeLinkClient *client)
{
    client->active = false;
}

char *HomeLinkClient__readFile(const HomeLinkClient *client, const char *directory)
{

    HomeLinkClient__sendCommand(client->syncSocket, client, "READ_FILE");

    uint8_t buffer[1] = {0};
    bool status = recvBufferTcp(client->syncSocket, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        return NULL;
    }

    if (buffer[0] == 0)
    {
        // No file, return empty string
        return (char *)calloc(1, 1);
    }

    char prefix[256] = {0};
    char lastChar = '\0';
    size_t len = 0;
    if (directory != NULL)
    {
        for (const char *ptr = directory; *ptr != '\0'; ++ptr)
        {
            lastChar = *ptr;
            prefix[len++] = *ptr;
        }
    }
    if (lastChar != '/')
    {
        prefix[len++] = '/';
    }

    char *filePath = recvFile(client->syncSocket, prefix, client->aesKey, e_ClientRecv);

    return filePath;
}

bool HomeLinkClient__writeFile(const HomeLinkClient *client, const char *destinationHostId, const char *destinationServiceId, const char *localPath, const char *remotePath)
{
    char command[168] = {0};

    struct stat st;
    memset(&st, 0, sizeof(st));
    int rc = stat(localPath, &st);
    if (rc < 0)
    {
        fprintf(stderr, "stat() failed, file may not exist\n");
        return false;
    }

    const uint64_t fileSize = st.st_size;

    snprintf(command, sizeof(command) - 1, "WRITE_FILE %s %s %s %llu", destinationHostId, destinationServiceId, remotePath, (unsigned long long)fileSize);

    HomeLinkClient__sendCommand(client->syncSocket, client, command);

    bool status = sendFile(client->syncSocket, localPath, remotePath, client->aesKey, 0);

    memset(&command, 0, sizeof(command));

    return status;
}

void HomeLinkClient__delete(HomeLinkClient **client)
{
    sleep(1);
    if ((*client)->syncSocket >= 0)
    {
        close((*client)->syncSocket);
    }
    if ((*client)->asyncFileSocket >= 0)
    {
        close((*client)->asyncFileSocket);
    }

    if ((*client)->asyncFileThreadId != 0)
    {
        pthread_join((*client)->asyncFileThreadId, NULL);
    }

    EVP_PKEY_free((*client)->keypair);
    memset(*client, 0, HomeLinkClient_SIZE);
    free(*client);
    *client = NULL;
}
