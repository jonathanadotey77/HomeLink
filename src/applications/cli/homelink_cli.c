#include <homelink_client.h>
#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <termios.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t MAX_PASSWORD_LEN = 1024;

typedef struct HomeLinkConfig
{
    char hostId[33];
    char serverAddress[65];
    char serverPort[33];
} HomeLinkConfig;

void getPassword(char *password)
{
    static struct termios old_terminal;
    static struct termios new_terminal;

    tcgetattr(STDIN_FILENO, &old_terminal);

    new_terminal = old_terminal;
    new_terminal.c_lflag &= ~(ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

    if (fgets(password, 1023, stdin) == NULL)
    {
        password[0] = '\0';
    }
    else
    {
        password[strlen(password) - 1] = '\0';
        password[1023] = '\0';
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
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
            if (stringEqual(key, "host_id"))
            {
                strncpy(config->hostId, value, sizeof(config->hostId));
            }
            else if (stringEqual(key, "server_address"))
            {
                strncpy(config->serverAddress, value, sizeof(config->serverAddress));
            }
            else if (stringEqual(key, "server_port"))
            {
                strncpy(config->serverPort, value,
                        sizeof(config->serverPort));
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

        if (stringEqual(token, "--host-id"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }
            strncpy(config.hostId, field, sizeof(config.hostId) - 1);
        }
        else if (stringEqual(token, "--server-address"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverAddress, field, sizeof(config.serverAddress));
        }
        else if (stringEqual(token, "--server-port"))
        {
            char *field = strtok(NULL, "=");
            if (field == NULL || strlen(field) == 0)
            {
                fprintf(stderr, "Field for %s cannot be empty\n", token);
                return false;
            }

            strncpy(config.serverPort, field,
                    sizeof(config.serverPort));
        }
    }

    FILE *file = fopen(configFilePath, "w");

    fprintf(file, "host_id %s\n", config.hostId);
    fprintf(file, "server_address %s\n", config.serverAddress);
    fprintf(file, "server_port %s\n", config.serverPort);

    fclose(file);

    return true;
}

void shutdownCli(HomeLinkClient **client)
{
    HomeLinkClient__logout(*client);
    HomeLinkClient__delete(client);
    cleanSecurity();
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

    HomeLinkClient *client = HomeLinkClient__create(config.hostId, argv[1], config.serverAddress, atoi(config.serverPort));
    if (client == NULL)
    {
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    if (!HomeLinkClient__connect(client))
    {
        HomeLinkClient__delete(&client);
        return 1;
    }

    if (argc == 2 && stringEqual("--register-host", argv[1]))
    {
        RegisterStatus status = (RegisterStatus)HomeLinkClient__registerHost(client);

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

        HomeLinkClient__delete(&client);
        cleanSecurity();

        return 0;
    }

    if (argc == 3 && stringEqual("--register-service", argv[1]))
    {
        char password1[8192];
        char password2[8192];
        memset(password1, 0, sizeof(password1));
        memset(password2, 0, sizeof(password2));

        const char *serviceId = argv[2];

        printf("Enter password:\n");
        getPassword(password1);
        printf("Re-enter password:\n");
        getPassword(password2);

        if (!stringEqual(password1, password2))
        {
            printf("|%s %s\n", password1, password2);
            printf("Passwords do not match!\n");
            HomeLinkClient__delete(&client);
            cleanSecurity();
            return 0;
        }

        if (strlen(password1) >= MAX_PASSWORD_LEN)
        {
            printf("Password too long!\n");
            HomeLinkClient__delete(&client);
            cleanSecurity();
            return 0;
        }

        RegisterStatus status = HomeLinkClient__registerService(client, serviceId, password1);

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

        if (status == e_RegisterSuccess || status == e_AlreadyExists)
        {
            HomeLinkClient__login(client, password1);
        }

        memset(password1, 0, sizeof(password1));
        memset(password2, 0, sizeof(password2));

        shutdownCli(&client);

        return 0;
    }

    char *password = calloc(8192, sizeof(char));
    printf("Enter password:\n");
    getPassword(password);
    if (strlen(password) > MAX_PASSWORD_LEN)
    {
        printf("Login failed\n");
    }

    if (HomeLinkClient__login(client, password) != e_LoginSuccess)
    {
        printf("Login failed\n");
        memset(password, 0, 8192);
        free(password);
        shutdownCli(&client);
        return 1;
    }

    memset(password, 0, 8192);
    free(password);

    handleCommand(client, argc - 2, argv + 2);

    shutdownCli(&client);

    return 0;
}