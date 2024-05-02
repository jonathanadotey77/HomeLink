#include <homelink_client.h>

#include <homelink_misc.h>
#include <homelink_net.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

static const int RETRY_COUNT = 5;

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
    client->serverControlPort = 0;
    client->serverDataPort = 0;

    for (int i = 0; i < argc; ++i)
    {
        char arg[128] = {0};
        strncpy(arg, argv[i], sizeof(arg) - 1);

        char *token = strtok(arg, "=");
        if (token == NULL)
        {
            continue;
        }

        const char *hostId = "--host-id";
        const size_t hostIdLen = strlen(hostId);

        const char *serverIpAddress = "--server-address";
        const size_t serverIpAddressLen = strlen(serverIpAddress);

        const char *serverControlPort = "--server-control-port";
        const size_t serverControlPortLen = strlen(serverControlPort);

        const char *serverDataPort = "--server-data-port";
        const size_t serverDataPortLen = strlen(serverDataPort);

        if (strlen(token) == hostIdLen && strncmp(token, hostId, hostIdLen) == 0)
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }
            strncpy(client->hostId, field, sizeof(client->hostId) - 1);
        }

        else if (strlen(token) == serverIpAddressLen && strncmp(token, serverIpAddress, serverIpAddressLen) == 0)
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(client->serverControlAddressStr, field, sizeof(client->serverControlAddressStr));
        }

        else if (strlen(token) == serverControlPortLen && strncmp(token, serverControlPort, serverControlPortLen) == 0)
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

            client->serverControlPort = (uint16_t)i;
        }

        else if (strlen(token) == serverDataPortLen && strncmp(token, serverDataPort, serverDataPortLen) == 0)
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

            client->serverDataPort = (uint16_t)i;
        }
    }

    if (client->serverControlAddressStr[0] == 0)
    {
        fprintf(stderr, "--server-address is a required argument for client intialization\n");
        return false;
    }
    if (client->hostId[0] == 0)
    {
        fprintf(stderr, "--host-id is a required argument for client intialization\n");
        return false;
    }
    if (client->serverControlPort == 0)
    {
        fprintf(stderr, "--control-port is a required argument for client intialization\n");
        return false;
    }
    if (client->serverDataPort == 0)
    {
        fprintf(stderr, "--data-port is a required argument for client intialization\n");
        return false;
    }

    client->serverControlAddress.sin6_family = AF_INET6;
    struct in6_addr serverInAddress = parseIpAddress(client->serverControlAddressStr);
    memcpy(&client->serverControlAddress.sin6_addr, &serverInAddress, sizeof(client->serverControlAddress.sin6_addr));
    client->serverControlAddress.sin6_port = htons(client->serverControlPort);
    client->serverControlAddress.sin6_flowinfo = 0;
    client->serverControlAddress.sin6_scope_id = 0;

    client->serverDataAddress.sin6_family = AF_INET6;
    memcpy(&client->serverDataAddress.sin6_addr, &serverInAddress, sizeof(client->serverDataAddress.sin6_addr));
    client->serverDataAddress.sin6_port = htons(client->serverDataPort);
    client->serverDataAddress.sin6_flowinfo = 0;
    client->serverDataAddress.sin6_scope_id = 0;

    client->clientControlAddress.sin6_family = AF_INET6;
    client->clientControlAddress.sin6_addr = in6addr_any;
    client->clientControlAddress.sin6_scope_id = 0;
    client->clientControlAddress.sin6_flowinfo = 0;

    client->clientDataAddress.sin6_family = AF_INET6;
    client->clientDataAddress.sin6_addr = in6addr_any;
    client->clientDataAddress.sin6_scope_id = 0;
    client->clientDataAddress.sin6_flowinfo = 0;

    char out1[1024] = {0};
    getIpv6Str(out1, &client->clientControlAddress.sin6_addr);

    char out2[1024] = {0};
    getIpv6Str(out2, &client->clientDataAddress.sin6_addr);

    client->controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (client->controlSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        return false;
    }

    bool bound = false;
    for (int i = 0; i < 10; ++i)
    {
        uint16_t port = randomPort(50000, 59999);
        client->clientControlAddress.sin6_port = htons(port);
        if (bind(client->controlSocket, (const struct sockaddr *)&client->clientControlAddress, sizeof(client->clientControlAddress)) >= 0)
        {
            bound = true;
            break;
        }
    }

    if (!bound)
    {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        close(client->controlSocket);
        return false;
    }

    if (connect(client->controlSocket, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d\n]", errno);
        close(client->controlSocket);
    }

    strncpy(client->serviceId, serviceId, sizeof(client->serviceId));

    client->connectionId = 0;

    return true;
}

bool HomeLinkClient__fetchKeys(HomeLinkClient *client)
{
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    struct sockaddr_in6 sourceAddress = {0};
    socklen_t sourceAddressLen = sizeof(sourceAddress);

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
        int rc = sendto(client->controlSocket, buffer, KeyRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            return false;
        }

        memset(buffer, 0, sizeof(buffer));

        fds[0].fd = client->controlSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            return false;
        }
        else if (rc == 0)
        {
            continue;
        }

        sourceAddressLen = sizeof(sourceAddress);

        rc = recvfrom(client->controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recvfrom() failed [%d]\n", errno);
            return false;
        }

        if ((HomeLinkPacketType)buffer[0] != e_KeyResponse)
        {
            continue;
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

    return false;
}

RegisterStatus HomeLinkClient__registerHost(HomeLinkClient *client)
{
    const char *hostKey = getHostKey();
    if (hostKey == NULL)
    {
        fprintf(stderr, "Failed to read host key\n");
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
        bool status = rsaEncrypt(registerRequestPacket.data, &len, data, sizeof(data), client->serverPublicKey);
        if (!status)
        {
            fprintf(stderr, "rsaEncrypt() failed\n");
            return e_RegisterFailed;
        }

        memset(data, 0, sizeof(data));

        struct sockaddr_in6 sourceAddress = {0};
        socklen_t sourceAddressLen = sizeof(sourceAddress);

        RegisterRequestPacket_serialize(buffer, &registerRequestPacket);
        int rc = sendto(client->controlSocket, buffer, RegisterRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            return e_RegisterFailed;
        }

        memset(buffer, 0, sizeof(buffer));
        rc = recvfrom(client->controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recvfrom() failed [%d]\n", errno);
            return e_RegisterFailed;
        }

        if (rc == RegisterResponsePacket_SIZE && buffer[0] == e_RegisterResponse)
        {
            break;
        }

        if (i + 1 == RETRY_COUNT)
        {
            return e_RegisterFailed;
        }
    }

    RegisterResponsePacket registerResponsePacket = {0};
    RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

    return registerResponsePacket.status;
}

RegisterStatus HomeLinkClient__registerService(HomeLinkClient *client, const char *serviceId, const char *password)
{
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    struct sockaddr_in6 sourceAddress = {0};
    socklen_t sourceAddressLen = sizeof(sourceAddress);

    char *hashedPassword = hashPassword(password, strlen(password));
    uint8_t passwordData[192] = {0};

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

        int rc = sendto(client->controlSocket, buffer, RegisterRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            return false;
        }

        fds[0].fd = client->controlSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            return false;
        }
        else if (rc == 0)
        {
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        sourceAddressLen = sizeof(sourceAddress);

        rc = recvfrom(client->controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recvfrom() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            return e_RegisterFailed;
        }

        if (rc == 0 || buffer[0] != e_RegisterResponse || rc != RegisterResponsePacket_SIZE)
        {
            continue;
        }

        RegisterResponsePacket registerResponsePacket;
        RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

        memset(passwordData, 0, sizeof(passwordData));
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
    return e_RegisterFailed;
}

bool HomeLinkClient__login(HomeLinkClient *client, const char *password)
{
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    struct sockaddr_in6 sourceAddress = {0};
    socklen_t sourceAddressLen = sizeof(sourceAddress);

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

        int rc = sendto(client->controlSocket, buffer, LoginRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            return false;
        }

        fds[0].fd = client->controlSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            memset(passwordData, 0, sizeof(passwordData));
            return false;
        }
        else if (rc == 0)
        {
            continue;
        }

        rc = recvfrom(client->controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recvfrom() failed [%d]\n", errno);
            return false;
        }

        if (rc == 0 || buffer[0] != e_LoginResponse || rc != LoginResponsePacket_SIZE)
        {
            continue;
        }

        LoginResponsePacket loginResponsePacket;
        LoginResponsePacket_deserialize(&loginResponsePacket, buffer);

        LoginStatus status = loginResponsePacket.status;

        if (status == e_LoginFailed)
        {
            fprintf(stderr, "Incorrect password\n");
            return false;
            memset(passwordData, 0, sizeof(passwordData));
        }
        else if (status == e_LoginSuccess)
        {
            size_t len = sizeof(client->sessionKey);
            rsaDecrypt((uint8_t *)client->sessionKey, &len, loginResponsePacket.sessionKey, sizeof(loginResponsePacket.sessionKey), NULL);
            break;
        }
        else
        {
            fprintf(stderr, "Login error\n");
            memset(passwordData, 0, sizeof(passwordData));
            return false;
        }
    }

    memset(passwordData, 0, sizeof(passwordData));

    return true;
}

void HomeLinkClient__logout(HomeLinkClient *client)
{
    uint8_t buffer[1024] = {0};
    LogoutPacket logoutPacket;
    memset(&logoutPacket, 0, sizeof(logoutPacket));
    logoutPacket.packetType = e_Logout;
    logoutPacket.connectionId = client->connectionId;
    size_t len = sizeof(logoutPacket.sessionKey);
    rsaEncrypt(logoutPacket.sessionKey, &len, (uint8_t *)client->sessionKey, strlen(client->sessionKey) + 1, client->serverPublicKey);

    LogoutPacket_serialize(buffer, &logoutPacket);
    sendto(client->controlSocket, buffer, LogoutPacket__SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
}

char *HomeLinkClient__readFile(HomeLinkClient *client, const char *directory)
{
    int sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return NULL;
    }

    if (connect(sd, (const struct sockaddr *)&client->serverDataAddress, sizeof(client->serverDataAddress)) < 0)
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
        close(client->controlSocket);
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

    if (connect(sd, (const struct sockaddr *)&client->serverDataAddress, sizeof(client->serverDataAddress)) < 0)
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
    close(client->controlSocket);
}
