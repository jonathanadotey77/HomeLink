#include <homelink_buffer.h>
#include <homelink_keyset.h>
#include <homelink_misc.h>

#include <arpa/inet.h>
#include <iostream>
#include <mutex>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

uint16_t listenerPort = 10000;
uint16_t serverStartPort = 10001;
uint16_t numPorts = 10;

int controlSocket = -1;
int *dataSockets = NULL;

struct sockaddr_in6 listenerAddress;
struct sockaddr_in6 *dataAddresses;

pthread_t listenerThreadId = 0;
pthread_t commandThreadId = 0;

std::mutex serverLock;

std::unordered_map<std::string, KeySet> controlKeys;

bool parseArgs(int argc, char *argv[])
{
    int i = 1;
    while (i < argc)
    {
        std::string command(argv[i]);

        if (command == "--start-port")
        {
            int p = atoi(argv[i + 1]);
            if (p > UINT16_MAX || p <= 0)
            {
                std::cerr << "Invalid start port" << std::endl;
                return false;
            }
            i += 2;
        }
        else if (command == "--num-ports")
        {
            int n = atoi(argv[i + 1]);
            i += 2;
        }
        else
        {
            std::cerr << "Invalid command '" << std::string(argv[i]) << "'" << std::endl;
            return false;
        }
    }

    return true;
}

void* commandThread(void* a) {
    return NULL;
}

void* listenerThread(void* a) {
    if(1) return NULL;
    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);
    uint8_t buffer[1024];
    int rc = 0;
    while(true) {
        rc = recvfrom(controlSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&sourceAddress), &sourceAddressLen);

    }

    return NULL;
}

bool start()
{
    memset(&listenerAddress, 0, sizeof(listenerAddress));
    controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if(controlSocket < 0) {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return false;
    }

    dataSockets = new int[numPorts];
    dataAddresses = new struct sockaddr_in6[numPorts];

    listenerAddress.sin6_family = AF_INET6;
    listenerAddress.sin6_addr = in6addr_any;
    listenerAddress.sin6_port = htons(listenerPort);
    listenerAddress.sin6_flowinfo = 0;
    listenerAddress.sin6_scope_id = 0;

    if(bind(controlSocket, reinterpret_cast<const sockaddr*>(&listenerAddress), sizeof(listenerAddress)) < 0) {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        return false;
    }

    for (uint16_t i = 0; i < numPorts; ++i)
    {
        bool failed = false;
        dataSockets[i] = socket(AF_INET6, SOCK_STREAM, 0);
        dataAddresses[i].sin6_family = AF_INET6;
        dataAddresses[i].sin6_addr = in6addr_any;
        dataAddresses[i].sin6_port = htons(serverStartPort + i);
        dataAddresses[i].sin6_flowinfo = 0;
        dataAddresses[i].sin6_scope_id = 0;

        if (dataSockets[i] < 0)
        {
            fprintf(stderr, "socket() failed [%d]\n", errno);
            failed = true;
        }

        if (!failed && bind(dataSockets[i], reinterpret_cast<const struct sockaddr *>(&dataAddresses[i]), sizeof(dataAddresses[i])) < 0)
        {
            fprintf(stderr, "bind() failed [%d]\n", errno);
            failed = true;
        }

        if (failed)
        {
            for (uint16_t j = 0; j < i; ++j)
            {
                close(dataSockets[i]);
            }
            return false;
        }
    }

    pthread_create(&commandThreadId, NULL, commandThread, NULL);
    pthread_create(&listenerThreadId, NULL, listenerThread, NULL);

    return true;
}

void stop()
{
    close(controlSocket);
    for (int i = 0; i < numPorts; ++i)
    {
        close(dataSockets[i]);
    }

    delete[] dataAddresses;
    delete[] dataSockets;

    pthread_join(commandThreadId, NULL);
    pthread_join(listenerThreadId, NULL);
}

int main(int argc, char *argv[])
{
    if (!parseArgs(argc, argv))
    {
        return 1;
    }

    if (!start())
    {
        return 1;
    }

    std::cout << "HomeLink server listening on port " << listenerPort << std::endl;

    stop();

    std::cout << "Homelink server stopped" << std::endl;

    return 0;
}