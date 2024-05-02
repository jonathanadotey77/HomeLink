#include <homelink_client.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *serviceId = "DAEMON";
const char *daemonPassword = "PASSWORD717171717171717";
char daemonDirectory[256] = {0};
HomeLinkClient *client = NULL;

volatile bool stopped = false;

void shutdownHandler(int sig)
{
    if (sig)
    {
    }
    stopped = true;
}

void shutdownDaemon()
{
    HomeLinkClient__logout(client);
    HomeLinkClient__destruct(client);
    free(client);
}

void run()
{
    while (!stopped)
    {
        char *filename = HomeLinkClient__readFile(client, daemonDirectory);
        if (filename == NULL)
        {
            printf("File read error\n");
            sleep(5);
            continue;
        }

        if (strlen(filename) > 0)
        {
            printf("Received file: %s\n", filename);
        }
        else
        {
            printf("File queue is empty\n");
            sleep(5);
        }

        free(filename);
    }
}

int main(int argc, char **argv)
{
    if (!initializeSecurity())
    {
        return false;
    }

    client = (HomeLinkClient *)calloc(1, HomeLinkClient__SIZE);

    signal(SIGINT, shutdownHandler);
    signal(SIGTSTP, shutdownHandler);

    char *dir = getenv("HOMELINK_DAEMON_FILES");
    if (dir == NULL)
    {
        fprintf(stderr, "Environment variable HOMELINK_DAEMON_FILES is empty or not set\n");
        cleanSecurity();
        free(client);
        return 1;
    }
    strncpy(daemonDirectory, dir, sizeof(daemonDirectory) - 2);
    if (strlen(daemonDirectory) == 0)
    {
        fprintf(stderr, "Environment variable HOMELINK_DAEMON_FILES is empty or not set\n");
        free(client);
        return 1;
    }
    daemonDirectory[strlen(daemonDirectory)] = '/';

    if (!HomeLinkClient__initialize(client, "DAEMON", argc - 1, argv + 1))
    {
        cleanSecurity();
        free(client);
        return 1;
    }

    if (!HomeLinkClient__fetchKeys(client))
    {
        cleanSecurity();
        shutdownDaemon();
        return 1;
    }

    RegisterStatus status = HomeLinkClient__registerService(client, "DAEMON", daemonPassword);
    if (status == e_RegisterFailed)
    {
        fprintf(stderr, "Register failed\n");
        cleanSecurity();
        shutdownDaemon();
    }

    if (!HomeLinkClient__login(client, daemonPassword))
    {
        fprintf(stderr, "Login failed\n");
        cleanSecurity();
        shutdownDaemon();
        return 1;
    }

    run();

    cleanSecurity();
    shutdownDaemon();

    return 0;
}
