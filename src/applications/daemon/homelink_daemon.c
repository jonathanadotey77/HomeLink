#include <homelink_loginstatus.h>
#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char hostId[1024];
const char *serviceId = "DAEMON";
const char *daemonPassword = "PASSWORD717171717171717";

char serverAddressStr[64];
uint16_t serverPort;

char passwordStr[65];

int controlSocket = -1;
int dataSocket = -1;

struct sockaddr_in6 serverAddress;

char daemonPublicKey[512] = {0};
char serverPublicKey[512] = {0};
char username[2048] = {0};

bool readConfig()
{
    memset(hostId, 0, sizeof(hostId));
    memset(&serverAddress, 0, sizeof(serverAddress));
    memset(&serverAddressStr, 0, sizeof(serverAddressStr));
    serverPort = 0;
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
                strncpy(hostId, value, sizeof(hostId));
            }
            else if (strncmp(key, "server_address", sizeof("server_address") - 1) == 0)
            {
                strncpy(serverAddressStr, value, sizeof(serverAddressStr));
            }
            else if (strncmp(key, "server_port", sizeof("server_port") - 1) == 0)
            {
                serverPort = (uint16_t)atoi(value);
                if (serverPort == 0)
                {
                    fprintf(stderr, "Server port cannot be zero\n");
                    return false;
                }
            }
            else if (strncmp(key, "password", sizeof("password") - 1) == 0)
            {
                strncpy(passwordStr, value, sizeof(passwordStr) - 1);
                passwordStr[sizeof(passwordStr) - 1] = '\0';
            }
        }
    }

    if (serverAddressStr[0] == 0)
    {
        fprintf(stderr, "Server address not found in config file\n");
        return false;
    }
    if (hostId[0] == 0)
    {
        fprintf(stderr, "Host ID not found in config file\n");
        return false;
    }
    if (serverPort == 0)
    {
        fprintf(stderr, "Server port not found in config file\n");
        return false;
    }

    serverAddress.sin6_family = AF_INET6;
    struct in6_addr serverInAddress = parseIpAddress(serverAddressStr);
    memcpy(&serverAddress.sin6_addr, &serverInAddress, sizeof(serverAddress.sin6_addr));
    serverAddress.sin6_port = htons(serverPort);
    serverAddress.sin6_flowinfo = 0;
    serverAddress.sin6_scope_id = 0;

    fclose(file);
    return true;
}

bool init()
{
    if (!initializeSecurity())
    {
        return false;
    }
    controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (controlSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        cleanSecurity();
        return false;
    }

    dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (dataSocket < 0)
    {
        fprintf(stderr, "socket() failed\n");
        close(controlSocket);
        cleanSecurity();
        return false;
    }

    snprintf(username, sizeof(username), "%s__%s", hostId, serviceId);
    printf("U: %s\n", username);

    return true;
}

void shutdownDaemon()
{
    close(controlSocket);
    close(dataSocket);
    cleanSecurity();
}

bool login()
{
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);

    KeyRequestPacket keyRequestPacket;
    memset(&keyRequestPacket, 0, sizeof(keyRequestPacket));

    uint32_t connectionId = 0;

    size_t daemonPublicKeyLen = 0;
    getRSAPublicKey(daemonPublicKey, &daemonPublicKeyLen);

    keyRequestPacket.packetType = e_KeyRequest;
    memcpy(keyRequestPacket.rsaPublicKey, daemonPublicKey, sizeof(keyRequestPacket.rsaPublicKey));

    uint8_t buffer[1024] = {0};

    KeyRequestPacket_serialize(buffer, &keyRequestPacket);
    printf("%s\n", keyRequestPacket.rsaPublicKey);

    int rc = 0;

    while (true)
    {
        randomBytes((uint8_t *)&connectionId, sizeof(connectionId));
        keyRequestPacket.connectionId = connectionId;
        rc = sendto(controlSocket, buffer, KeyRequestPacket_SIZE, 0, (const struct sockaddr *)&serverAddress, sizeof(serverAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            return false;
        }

        memset(buffer, 0, sizeof(buffer));

        fds[0].fd = controlSocket;
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

        rc = recvfrom(controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recvfrom() failed [%d]\n", errno);
            return false;
        }

        KeyResponsePacket keyResponsePacket;
        memset(&keyResponsePacket, 0, sizeof(keyResponsePacket));

        KeyResponsePacket_deserialize(&keyResponsePacket, buffer);

        strncpy(serverPublicKey, keyResponsePacket.rsaPublicKey, sizeof(keyResponsePacket.rsaPublicKey) - 1);

        if (keyResponsePacket.success == 0)
        {
            fprintf(stderr, "Key request failed\n");
            continue;
        }

        break;
    }

    char *hashedPassword = hashPassword(daemonPassword, strlen(daemonPassword));
    uint8_t passwordData[128] = {0};
    strncpy((char *)(passwordData) + 32, hashedPassword, strlen(hashedPassword));

    while (true)
    {
        RegisterRequestPacket registerRequestPacket;
        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));

        randomBytes(passwordData, 32);
        randomBytes(passwordData + 104, 24);

        registerRequestPacket.packetType = e_RegisterRequest;
        registerRequestPacket.connectionId = connectionId;
        strncpy(registerRequestPacket.username, username, sizeof(registerRequestPacket.username) - 1);

        size_t len = sizeof(registerRequestPacket.data);
        rsaEncrypt(registerRequestPacket.data, &len, passwordData, sizeof(passwordData), serverPublicKey);

        memset(buffer, 0, sizeof(buffer));
        RegisterRequestPacket_serialize(buffer, &registerRequestPacket);

        rc = sendto(controlSocket, buffer, RegisterRequestPacket_SIZE, 0, (const struct sockaddr *)&serverAddress, sizeof(serverAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }

        fds[0].fd = controlSocket;
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

        rc = recvfrom(controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
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
        rsaEncrypt(loginRequestPacket.data, &len, passwordData, sizeof(passwordData), serverPublicKey);

        memset(buffer, 0, sizeof(buffer));

        LoginRequestPacket_serialize(buffer, &loginRequestPacket);

        rc = sendto(controlSocket, buffer, LoginRequestPacket_SIZE, 0, (const struct sockaddr *)&serverAddress, sizeof(serverAddress));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            memset(hashedPassword, 0, strlen(hashedPassword));
            free(hashedPassword);
            return false;
        }

        fds[0].fd = controlSocket;
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

        rc = recvfrom(controlSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
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

    return true;
}

int main()
{
    if (!readConfig())
    {
        return 1;
    }

    if (!init())
    {
        return 1;
    }

    if (!login())
    {
        shutdownDaemon();
        fprintf(stderr, "Login failed\n");
        return 1;
    }

    shutdownDaemon();

    return 0;
}