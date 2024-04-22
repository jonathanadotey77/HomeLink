#include <homelink_client.h>
#include <homelink_loginstatus.h>
#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *serviceId = "DAEMON";
const char *daemonPassword = "PASSWORD717171717171717";

HomeLinkClient client;

void shutdownDaemon()
{
    HomeLinkClient__logout(&client);
}

void run() {
    printf("Login success\n");

    HomeLinkClient__writeFile(&client, client.hostId, serviceId, "t.txt", "t1.txt");
    char* filename = HomeLinkClient__readFile(&client, NULL);

    if(filename != NULL) {
        printf("Read file\n");
        free(filename);
    }
    printf("Done\n");
}

int main()
{
    if (!initializeSecurity())
    {
        return false;
    }

    memset(&client, 0, sizeof(client));

    if (!HomeLinkClient__initialize(&client, "DAEMON"))
    {
        cleanSecurity();
        return 1;
    }

    if (!HomeLinkClient__login(&client, daemonPassword))
    {
        cleanSecurity();
        shutdownDaemon();
        fprintf(stderr, "Login failed\n");
        return 1;
    }

    run();

    cleanSecurity();
    shutdownDaemon();

    return 0;
}
