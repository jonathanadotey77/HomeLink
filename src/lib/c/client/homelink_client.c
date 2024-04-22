#include <homelink_client.h>

#include <homelink_loginstatus.h>
#include <homelink_misc.h>
#include <homelink_net.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

static void HomeLinkClient__sendCommand(HomeLinkClient* client, const char* command) {
    CommandPacket commandPacket;
    memset(&commandPacket, 0, sizeof(commandPacket));

    commandPacket.packetType = e_Command;
    commandPacket.connectionId = client->connectionId;

    size_t len = sizeof(commandPacket.sessionToken);
    rsaEncrypt(commandPacket.sessionToken, &len, (uint8_t *)client->sessionKey, strlen(client->sessionKey) + 1, client->serverPublicKey);

    char commandData[200] = {0};
    len = sizeof(commandPacket.data);
    randomBytes((uint8_t *)commandData, 32);
    strncpy(commandData, command, sizeof(commandData) - 32 - 1);
    rsaEncrypt(commandPacket.data, &len, (uint8_t *)commandData, sizeof(commandData), client->serverPublicKey);

    uint8_t buffer[CommandPacket_SIZE];
    CommandPacket_serialize(buffer, &commandPacket);

    sendBufferTcp(client->dataSocket, buffer, sizeof(buffer));
}

bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId)
{
    memset(client, 0, sizeof(HomeLinkClient));
    client->serverControlPort = 0;
    const char *configFilePath = getenv("HOMELINK_CONFIG_PATH");

    if (!configFilePath)
    {
        fprintf(stderr, "HOMELINK_CONFIG_PATH not set\n");
        return false;
    }

    FILE *file = fopen(configFilePath, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Could not open config file\n");
        return false;
    }

    char line[1024];
    char *key, *value;

    while (fgets(line, sizeof(line), file) != NULL)
    {
        key = strtok(line, " ");
        value = strtok(NULL, " ");

        if (value != NULL)
        {
            value[strcspn(value, "\n")] = '\0';
        }

        if (key != NULL && value != NULL)
        {
            if (strncmp(key, "host_id", sizeof("host_id") - 1) == 0)
            {
                strncpy(client->hostId, value, sizeof(client->hostId));
            }
            else if (strncmp(key, "server_address", sizeof("server_address") - 1) == 0)
            {
                strncpy(client->serverControlAddressStr, value, sizeof(client->serverControlAddressStr));
            }
            else if (strncmp(key, "server_control_port", sizeof("server_control_port") - 1) == 0)
            {
                client->serverControlPort = (uint16_t)atoi(value);
                if (client->serverControlPort == 0)
                {
                    fprintf(stderr, "Server port cannot be zero\n");
                    fclose(file);
                    return false;
                }
            }
            else if (strncmp(key, "server_data_port", sizeof("server_data_port") - 1) == 0)
            {
                client->serverDataPort = (uint16_t)atoi(value);
                if (client->serverDataPort == 0)
                {
                    fprintf(stderr, "Server port cannot be zero\n");
                    fclose(file);
                    return false;
                }
            }
        }
    }

    if (client->serverControlAddressStr[0] == 0)
    {
        fprintf(stderr, "Server address not found in config file\n");
        fclose(file);
        return false;
    }
    if (client->hostId[0] == 0)
    {
        fprintf(stderr, "Host ID not found in config file\n");
        fclose(file);
        return false;
    }
    if (client->serverControlPort == 0)
    {
        fprintf(stderr, "Server control port not found in config file\n");
        fclose(file);
        return false;
    }
    if (client->serverDataPort == 0)
    {
        fprintf(stderr, "Server data port not found in config file\n");
        fclose(file);
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

    fclose(file);

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
        fprintf(stderr, "Could not bind to port\n");
        close(client->controlSocket);
        return false;
    }

    client->dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client->dataSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        close(client->controlSocket);
        return false;
    }

    strncpy(client->serviceId, serviceId, sizeof(client->serviceId));

    client->connectionId = 0;

    return true;
}

bool HomeLinkClient__login(HomeLinkClient *client, const char *password)
{
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);

    KeyRequestPacket keyRequestPacket;
    memset(&keyRequestPacket, 0, sizeof(keyRequestPacket));

    uint32_t connectionId = 0;

    size_t clientPublicKeyLen = 0;
    getRSAPublicKey(client->clientPublicKey, &clientPublicKeyLen);

    keyRequestPacket.packetType = e_KeyRequest;
    memcpy(keyRequestPacket.rsaPublicKey, client->clientPublicKey, sizeof(keyRequestPacket.rsaPublicKey));

    uint8_t buffer[1024] = {0};

    char username[1024] = {0};
    snprintf(username, sizeof(username), "%s__%s", client->hostId, client->serviceId);

    int rc = 0;

    while (true)
    {
        randomBytes((uint8_t *)&connectionId, sizeof(connectionId));
        keyRequestPacket.connectionId = connectionId;
        KeyRequestPacket_serialize(buffer, &keyRequestPacket);
        rc = sendto(client->controlSocket, buffer, KeyRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
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

        break;
    }
    char *hashedPassword = hashPassword(password, strlen(password));
    uint8_t passwordData[128] = {0};
    strncpy((char *)(passwordData) + 32, hashedPassword, strlen(hashedPassword));
    while (true)
    {
        RegisterRequestPacket registerRequestPacket;
        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));

        randomBytes(passwordData, 32);
        randomBytes(passwordData + 104, 24);

        strncpy(registerRequestPacket.hostId, client->hostId, sizeof(registerRequestPacket.hostId) - 1);
        strncpy(registerRequestPacket.serviceId, client->serviceId, sizeof(registerRequestPacket.serviceId) - 1);

        size_t len = sizeof(registerRequestPacket.data);
        rsaEncrypt(registerRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);

        registerRequestPacket.packetType = e_RegisterRequest;
        registerRequestPacket.connectionId = connectionId;

        memset(buffer, 0, sizeof(buffer));
        RegisterRequestPacket_serialize(buffer, &registerRequestPacket);

        rc = sendto(client->controlSocket, buffer, RegisterRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }

        fds[0].fd = client->controlSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
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
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }

        if (rc == 0 || buffer[0] != e_RegisterResponse || rc != RegisterResponsePacket_SIZE)
        {
            continue;
        }

        RegisterResponsePacket registerResponsePacket;
        RegisterResponsePacket_deserialize(&registerResponsePacket, buffer);

        if (registerResponsePacket.status == e_UserAlreadyExists || registerResponsePacket.status == e_LoginSuccess)
        {
            break;
        }
        else
        {
            fprintf(stderr, "Register error\n");
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }
    }

    while (true)
    {
        LoginRequestPacket loginRequestPacket;
        memset(&loginRequestPacket, 0, sizeof(loginRequestPacket));

        loginRequestPacket.packetType = e_LoginRequest;
        loginRequestPacket.connectionId = connectionId;
        strncpy(loginRequestPacket.hostId, client->hostId, sizeof(loginRequestPacket.hostId) - 1);
        strncpy(loginRequestPacket.serviceId, client->serviceId, sizeof(loginRequestPacket.serviceId) - 1);

        uint32_t tag = 0;
        randomBytes((uint8_t *)&tag, sizeof(tag));

        *((uint32_t *)passwordData) = htonl(tag);

        randomBytes(passwordData + 4, 28);
        randomBytes(passwordData + 104, 24);

        size_t len = sizeof(loginRequestPacket.data);
        rsaEncrypt(loginRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);

        memset(buffer, 0, sizeof(buffer));

        LoginRequestPacket_serialize(buffer, &loginRequestPacket);

        rc = sendto(client->controlSocket, buffer, LoginRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverControlAddress, sizeof(client->serverControlAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }

        fds[0].fd = client->controlSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
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
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
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
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
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
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }
    }

    memset(hashedPassword, 0, strlen(hashedPassword));
    free(hashedPassword);

    client->connectionId = connectionId;

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
    close(client->controlSocket);
    close(client->dataSocket);
}

bool HomeLinkClient__readFile(HomeLinkClient *client, const char* directory)
{

    if (connect(client->dataSocket, (const struct sockaddr *)&client->serverDataAddress, sizeof(client->serverDataAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
    }

    HomeLinkClient__sendCommand(client, "READ_FILE");

    bool status = recvFile(client->dataSocket, directory == NULL ? "" : directory, client->aesKey, false);

    close(client->dataSocket);
    client->dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client->dataSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        close(client->controlSocket);
        exit(1);
    }

    return status;
}

bool HomeLinkClient__writeFile(HomeLinkClient* client, const char* localPath, const char* remotePath) {

    char command[168] = {0};

    struct stat st;
    memset(&st, 0, sizeof(st));
    int rc = stat(localPath, &st);
    if(rc < 0) {
        return false;
    }


    const uint64_t fileSize = st.st_size;

    snprintf(command, sizeof(command)-1, "WRITE_FILE %s %llu", remotePath, (unsigned long long)fileSize);

    if (connect(client->dataSocket, (const struct sockaddr *)&client->serverDataAddress, sizeof(client->serverDataAddress)) < 0)
    {
        fprintf(stderr, "connect() failed [%d]\n", errno);
    }

    HomeLinkClient__sendCommand(client, command);

    bool status = sendFile(client->dataSocket, localPath, remotePath, client->aesKey);
    
    memset(&command, 0, sizeof(command));

    close(client->dataSocket);
    client->dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client->dataSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        exit(1);
    }

    return status;
}
