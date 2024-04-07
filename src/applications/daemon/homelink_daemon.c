#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char hostId[1024];
const char *serviceId = "DAEMON";

char serverAddressStr[64];
uint16_t serverPort;

int controlSocket = -1;
int dataSocket = -1;

struct sockaddr_in6 serverAddress;

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

    FILE *fp = NULL;

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
            if (strcmp(key, "host_id") == 0)
            {
                strncpy(hostId, value, sizeof(hostId));
            }
            else if (strcmp(key, "server_address") == 0)
            {
                strncpy(serverAddressStr, value, sizeof(serverAddressStr));
            }
            else if (strcmp(key, "server_port") == 0)
            {
                serverPort = (uint16_t)atoi(value);
                if (serverPort == 0)
                {
                    fprintf(stderr, "Server port cannot be zero\n");
                    return false;
                }
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
    if(!initializeSecurity()) {
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

    return true;
}

void shutdownDaemon()
{
    close(controlSocket);
    close(dataSocket);
    cleanSecurity();
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

    shutdownDaemon();

    return 0;
}