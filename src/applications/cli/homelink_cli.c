#include <homelink_client.h>
#include <homelink_security.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct HomeLinkConfig {
    char hostId[33];
    char serverAddress[65];
    char serverControlPort[33];
    char serverDataPort[33];
} HomeLinkConfig;

bool readConfig(HomeLinkConfig* config, const char* configFilePath) {

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
                strncpy(config->hostId, value, sizeof(config->hostId));
            }
            else if (strncmp(key, "server_address", sizeof("server_address") - 1) == 0)
            {
                strncpy(config->serverAddress, value, sizeof(config->serverAddress));
            }
            else if (strncmp(key, "server_control_port", sizeof("server_control_port") - 1) == 0)
            {
                strncpy(config->serverControlPort, value, sizeof(config->serverControlPort));
            }
            else if (strncmp(key, "server_data_port", sizeof("server_data_port") - 1) == 0)
            {
                strncpy(config->serverDataPort, value, sizeof(config->serverDataPort));
            }
        }
    }

    fclose(file);

    return true;
}

bool editConfig(int argc, char** argv, const char* configFilePath) {
    HomeLinkConfig config;
    readConfig(&config, configFilePath);

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
            char* field = strtok(NULL, "=");
            if(field == NULL || strlen(field) == 0) {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }
            strncpy(config.hostId, field, sizeof(config.hostId)-1);
        }

        else if (strlen(token) == serverIpAddressLen && strncmp(token, serverIpAddress, serverIpAddressLen) == 0)
        {
            char* field = strtok(NULL, "=");
            if(field == NULL || strlen(field) == 0) {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverAddress, field, sizeof(config.serverAddress));
        }

        else if (strlen(token) == serverControlPortLen && strncmp(token, serverControlPort, serverControlPortLen) == 0)
        {
            char* field = strtok(NULL, "=");
            if(field == NULL || strlen(field) == 0) {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverControlPort, field, sizeof(config.serverControlPort));
        }

        else if (strlen(token) == serverDataPortLen && strncmp(token, serverDataPort, serverDataPortLen) == 0)
        {
            char* field = strtok(NULL, "=");
            if(field == NULL || strlen(field) == 0) {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverDataPort, field, sizeof(config.serverDataPort));
        }
    }

    FILE* file = fopen(configFilePath, "w");

    fprintf(file, "host_id %s\n", config.hostId);
    fprintf(file, "server_address %s\n", config.serverAddress);
    fprintf(file, "server_control_port %s\n", config.serverControlPort);
    fprintf(file, "server_data_port %s\n", config.serverDataPort);

    fclose(file);

    return true;
}

int main(int argc, char** argv)
{
    if(argc < 2) {
        fprintf(stderr, "Need serviceId or --configure as first argument\n");
        return 1;
    }

    const char *configFilePath = getenv("HOMELINK_CLI_CONFIG_PATH");

    if (!configFilePath)
    {
        fprintf(stderr, "HOMELINK_CLI_CONFIG_PATH not set\n");
        return false;
    }

    if(argc >= 2 && strncmp("--configure", argv[1], strlen("--configure")) == 0) {
        bool success = editConfig(argc - 2, argv + 2, configFilePath);
        if(success) {
            printf("Config file changed\n");
        }
        return success ? 0 : 1;
    }

    if(!initializeSecurity()) {
        return 1;
    }

    HomeLinkConfig config;
    readConfig(&config, configFilePath);

    HomeLinkClient client;

    int argc2 = 4;

    char a0[33] = {0};
    char a1[33] = {0};
    char a2[33] = {0};
    char a3[33] = {0};

    snprintf(a0, 32, "--host-id=%s", config.hostId);
    snprintf(a1, 32, "--server-address=%s", config.serverAddress);
    snprintf(a2, 32, "--server-control-port=%s", config.serverControlPort);
    snprintf(a3, 32, "--server-data-port=%s", config.serverDataPort);

    char* argv2[4] = {a0, a1, a2, a3};

    if(!HomeLinkClient__initialize(&client, argv[1], argc2, argv2)) {
        return 1;
    }
    if(!HomeLinkClient__login(&client, "password")) {
        fprintf(stderr, "Login failed\n");
    }

    HomeLinkClient__logout(&client);
    cleanSecurity();

    return 0;
}