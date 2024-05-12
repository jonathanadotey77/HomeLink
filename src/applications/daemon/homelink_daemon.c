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
    printf("Stopping daemon\n");
    stopped = true;
    HomeLinkClient__stopAsync(client);
}

void shutdownDaemon()
{
    HomeLinkClient__logout(client);
    HomeLinkClient__delete(&client);
    free(client);
    cleanSecurity();
}

void callback(const char *filename, void *context)
{
    if (context)
    {
    }
    printf("Received file: %s\n", filename);
}

void run()
{

    bool status = HomeLinkClient__readFileAsync(client, daemonDirectory, callback, NULL);
    if (!status)
    {
        printf("Failed\n");
    }

    HomeLinkClient__waitAsync(client);
}

int main(int argc, char **argv)
{
    if (!initializeSecurity())
    {
        return false;
    }

    signal(SIGINT, shutdownHandler);
    signal(SIGTSTP, shutdownHandler);
    signal(SIGPIPE, SIG_IGN);

    char *dir = getenv("HOMELINK_DAEMON_FILES");
    if (dir == NULL)
    {
        fprintf(stderr, "Environment variable HOMELINK_DAEMON_FILES is empty or not set\n");
        cleanSecurity();
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

    client = HomeLinkClient__createWithArgs("DAEMON", argc - 1, (const char **)(argv + 1));
    if (client == NULL)
    {
        cleanSecurity();
        return 1;
    }

    if (!HomeLinkClient__fetchKeys(client))
    {
        shutdownDaemon();
        return 1;
    }

    RegisterStatus status = HomeLinkClient__registerService(client, "DAEMON", daemonPassword);
    if (status == e_RegisterFailed)
    {
        fprintf(stderr, "Register failed\n");
        shutdownDaemon();
    }

    if (HomeLinkClient__login(client, daemonPassword) != e_LoginSuccess)
    {
        fprintf(stderr, "Login failed\n");
        shutdownDaemon();
        return 1;
    }

    run();

    shutdownDaemon();

    return 0;
}
