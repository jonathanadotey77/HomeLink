#include <homelink_client.h>
#include <homelink_misc.h>
#include <homelink_security.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct HomeLinkConfig
{
    char hostId[33];
    char serverAddress[65];
    char serverControlPort[33];
    char serverDataPort[33];
} HomeLinkConfig;

bool stringEqual(const char *s1, const char *s2)
{
    if (strlen(s1) != strlen(s2))
    {
        return false;
    }

    return strcmp(s1, s2) == 0;
}

bool readConfig(HomeLinkConfig *config, const char *configFilePath)
{
    memset(config, 0, sizeof(HomeLinkConfig));
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
            else if (strncmp(key, "server_address", sizeof("server_address") - 1) ==
                     0)
            {
                strncpy(config->serverAddress, value, sizeof(config->serverAddress));
            }
            else if (strncmp(key, "server_control_port",
                             sizeof("server_control_port") - 1) == 0)
            {
                strncpy(config->serverControlPort, value,
                        sizeof(config->serverControlPort));
            }
            else if (strncmp(key, "server_data_port",
                             sizeof("server_data_port") - 1) == 0)
            {
                strncpy(config->serverDataPort, value, sizeof(config->serverDataPort));
            }
        }
    }

    fclose(file);

    return true;
}

bool editConfig(int argc, char **argv, const char *configFilePath)
{
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
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }
            strncpy(config.hostId, field, sizeof(config.hostId) - 1);
        }

        else if (strlen(token) == serverIpAddressLen &&
                 strncmp(token, serverIpAddress, serverIpAddressLen) == 0)
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverAddress, field, sizeof(config.serverAddress));
        }

        else if (strlen(token) == serverControlPortLen &&
                 strncmp(token, serverControlPort, serverControlPortLen) == 0)
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverControlPort, field,
                    sizeof(config.serverControlPort));
        }

        else if (strlen(token) == serverDataPortLen &&
                 strncmp(token, serverDataPort, serverDataPortLen) == 0)
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverDataPort, field, sizeof(config.serverDataPort));
        }
    }

    FILE *file = fopen(configFilePath, "w");

    fprintf(file, "host_id %s\n", config.hostId);
    fprintf(file, "server_address %s\n", config.serverAddress);
    fprintf(file, "server_control_port %s\n", config.serverControlPort);
    fprintf(file, "server_data_port %s\n", config.serverDataPort);

    fclose(file);

    return true;
}

void handleCommand(HomeLinkClient *client, int argc, char **argv)
{
    if (argc == 0)
    {
        return;
    }

    const char *command = argv[0];

    if (stringEqual(command, "get"))
    {
        char *prefix = NULL;
        if (argc == 2)
        {
            prefix = calloc(64, sizeof(char));

            strncpy(prefix, argv[1], 62);
            size_t idx = strlen(prefix);
            if (prefix[idx] != '/')
            {
                prefix[idx] = '/';
            }
        }

        char *filename =
            HomeLinkClient__readFile(client, prefix != NULL ? prefix : "");
        if (prefix != NULL)
        {
            free(prefix);
        }

        if (filename == NULL)
        {
            fprintf(stderr, "Error fetching file\n");
            return;
        }

        if (strlen(filename) > 0)
        {
            printf("Fetched file: %s\n", filename);
        }
        else
        {
            printf("No files in queue\n");
        }

        free(filename);
    }
    else if (stringEqual(command, "send"))
    {
        if (argc != 5)
        {
            fprintf(stderr, "Invalid command\n");
            return;
        }

        const char *hostId = argv[1];
        const char *serviceId = argv[2];
        const char *localPath = argv[3];
        const char *remotePath = argv[4];

        bool status = HomeLinkClient__writeFile(client, hostId, serviceId,
                                                localPath, remotePath);

        printf("Write %s\n", status ? "succeeded" : "failed");
    }
    else
    {
        fprintf(stderr, "Invalid command\n");
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Need serviceId or --configure as first argument\n");
        return 1;
    }

    const char *configFilePath = getenv("HOMELINK_CLI_CONFIG_PATH");

    if (!configFilePath)
    {
        fprintf(stderr, "HOMELINK_CLI_CONFIG_PATH not set\n");
        return false;
    }

    if (argc >= 2 && stringEqual("--configure", argv[1]))
    {
        bool success = editConfig(argc - 2, argv + 2, configFilePath);
        if (success)
        {
            printf("Config file changed\n");
        }
        return success ? 0 : 1;
    }

    if (!initializeSecurity())
    {
        return 1;
    }

    HomeLinkConfig config;
    readConfig(&config, configFilePath);

    HomeLinkClient *client = (HomeLinkClient *)calloc(1, HomeLinkClient__SIZE);

    int argc2 = 4;

    char a0[33] = {0};
    char a1[33] = {0};
    char a2[33] = {0};
    char a3[33] = {0};

    snprintf(a0, 32, "--host-id=%s", config.hostId);
    snprintf(a1, 32, "--server-address=%s", config.serverAddress);
    snprintf(a2, 32, "--server-control-port=%s", config.serverControlPort);
    snprintf(a3, 32, "--server-data-port=%s", config.serverDataPort);

    char *argv2[4] = {a0, a1, a2, a3};

    if (!HomeLinkClient__initialize(client, argv[1], argc2, argv2))
    {
        free(client);
        cleanSecurity();
        return 1;
    }

    if (!HomeLinkClient__fetchKeys(client))
    {
        free(client);
        cleanSecurity();
        return 1;
    }

    if (argc == 2 && stringEqual("--register-host", argv[1]))
    {
        RegisterStatus status = HomeLinkClient__registerHost(client);

        if (status == e_RegisterSuccess)
        {
            printf("Successfully register host ID %s\n", config.hostId);
        }
        else if (status == e_AlreadyExists)
        {
            printf("Host ID %s was already registered, host key validated\n", config.hostId);
        }
        else if (status == e_RegisterFailed)
        {
            printf("Registration failed\n");
        }

        free(client);
        cleanSecurity();

        return 0;
    }

    if (argc == 3 && stringEqual("--register-service", argv[1]))
    {
        const char *serviceId = argv[2];

        RegisterStatus status = HomeLinkClient__registerService(client, serviceId, "password");

        if (status == e_RegisterSuccess)
        {
            printf("Successfully service %s\n", serviceId);
        }
        else if (status == e_AlreadyExists)
        {
            printf("Service %s was already registered, password validated\n", serviceId);
        }
        else if (status == e_RegisterFailed)
        {
            printf("Registration failed\n");
        }

        free(client);
        cleanSecurity();

        return 0;
    }

    if (!HomeLinkClient__login(client, "password"))
    {
        fprintf(stderr, "Login failed\n");
        free(client);
        cleanSecurity();
        return 1;
    }

    handleCommand(client, argc - 2, argv + 2);

    HomeLinkClient__logout(client);
    HomeLinkClient__destruct(client);
    cleanSecurity();
    free(client);

    return 0;
}