#include <homelink_client.h>

#include <homelink_loginstatus.h>
#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

bool HomeLinkClient__initialize(HomeLinkClient *client, const char *serviceId)
{
    memset(client->hostId, 0, sizeof(client->hostId));
    memset(&client->serverAddress, 0, sizeof(client->serverAddress));
    memset(&client->serverAddressStr, 0, sizeof(client->serverAddressStr));
    client->serverPort = 0;
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
                strncpy(client->serverAddressStr, value, sizeof(client->serverAddressStr));
            }
            else if (strncmp(key, "server_port", sizeof("server_port") - 1) == 0)
            {
                client->serverPort = (uint16_t)atoi(value);
                if (client->serverPort == 0)
                {
                    fprintf(stderr, "Server port cannot be zero\n");
                    fclose(file);
                    return false;
                }
            }
        }
    }

    if (client->serverAddressStr[0] == 0)
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
    if (client->serverPort == 0)
    {
        fprintf(stderr, "Server port not found in config file\n");
        fclose(file);
        return false;
    }

    client->serverAddress.sin6_family = AF_INET6;
    struct in6_addr serverInAddress = parseIpAddress(client->serverAddressStr);
    memcpy(&client->serverAddress.sin6_addr, &serverInAddress, sizeof(client->serverAddress.sin6_addr));
    client->serverAddress.sin6_port = htons(client->serverPort);
    client->serverAddress.sin6_flowinfo = 0;
    client->serverAddress.sin6_scope_id = 0;

    fclose(file);

    client->controlAddress.sin6_family = AF_INET6;
    client->controlAddress.sin6_addr = in6addr_any;
    client->controlAddress.sin6_scope_id = 0;
    client->controlAddress.sin6_flowinfo = 0;

    client->dataAddress.sin6_family = AF_INET6;
    client->dataAddress.sin6_addr = in6addr_any;
    client->dataAddress.sin6_scope_id = 0;
    client->dataAddress.sin6_flowinfo = 0;

    char out1[1024] = {0};
    getIpv6Str(out1, &client->controlAddress.sin6_addr);

    char out2[1024] = {0};
    getIpv6Str(out2, &client->dataAddress.sin6_addr);

    client->controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (client->controlSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        return false;
    }

    bool bound = false;
    for(int i = 0; i < 10; ++i) {
        uint16_t port = randomPort(50000, 59999);
        client->controlAddress.sin6_port = htons(port);
        if(bind(client->controlSocket, (const struct sockaddr*)&client->controlAddress, sizeof(client->controlAddress)) >= 0) {
            bound = true;
            break;
        }
    }

    if(!bound) {
        fprintf(stderr, "Could not bind to port\n");
        close(client->controlSocket);
        return false;
    }

    bound = false;
    client->dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client->dataSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        close(client->controlSocket);
        return false;
    }

    for(int i = 0; i < 10; ++i) {
        uint16_t port = randomPort(50000, 59999);
        client->dataAddress.sin6_port = htons(port);
        if(bind(client->dataSocket, (const struct sockaddr*)&client->dataAddress, sizeof(client->dataAddress)) >= 0) {
            bound = true;
            break;
        }
    }

    if(!bound) {
        fprintf(stderr, "Could not bind to port\n");
        close(client->controlSocket);
        close(client->dataSocket);
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
        rc = sendto(client->controlSocket, buffer, KeyRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress));
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

        strncpy(registerRequestPacket.username, username, sizeof(registerRequestPacket.username) - 1);

        size_t len = sizeof(registerRequestPacket.data);
        rsaEncrypt(registerRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);

        registerRequestPacket.packetType = e_RegisterRequest;
        registerRequestPacket.connectionId = connectionId;

        memset(buffer, 0, sizeof(buffer));
        RegisterRequestPacket_serialize(buffer, &registerRequestPacket);

        rc = sendto(client->controlSocket, buffer, RegisterRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress));
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
        strncpy(loginRequestPacket.username, username, strlen(username));

        uint32_t tag = 0;
        randomBytes((uint8_t *)&tag, sizeof(tag));

        *((uint32_t *)passwordData) = htonl(tag);

        randomBytes(passwordData + 4, 28);
        randomBytes(passwordData + 104, 24);

        size_t len = sizeof(loginRequestPacket.data);
        rsaEncrypt(loginRequestPacket.data, &len, passwordData, sizeof(passwordData), client->serverPublicKey);

        memset(buffer, 0, sizeof(buffer));

        LoginRequestPacket_serialize(buffer, &loginRequestPacket);

        rc = sendto(client->controlSocket, buffer, LoginRequestPacket_SIZE, 0, (const struct sockaddr *)&client->serverAddress, sizeof(client->serverAddress));
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