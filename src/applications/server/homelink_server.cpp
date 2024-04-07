#include <homelink_keypair.h>
#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

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

volatile bool isStopped = false;

std::unordered_map<uint32_t, KeyPair> clientKeys;

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

void handleCommand(const struct sockaddr* sourceAddress, socklen_t sourceAddressLen, const char* command) {
    printf("%s\n", command);
}

void* commandThread(void* a) {
    struct sockaddr_in6 commandAddress;
    memset(&commandAddress, 0, sizeof(commandAddress));

    commandAddress.sin6_family = AF_INET6;
    commandAddress.sin6_addr = parseIpAddress("127.0.0.1");
    commandAddress.sin6_port = htons(45000);
    commandAddress.sin6_flowinfo = 0;
    commandAddress.sin6_scope_id = 0;

    int commandSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if(commandSocket < 0) {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return NULL;
    }

    if(bind(commandSocket, reinterpret_cast<const struct sockaddr*>(&commandAddress), sizeof(commandAddress)) < 0) {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        return NULL;
    }

    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);
    uint8_t buffer[1024];
    char data[256];
    CLIPacket cliPacket;
    size_t dataLen = sizeof(data);
    while(!isStopped) {
        memset(buffer, 0, sizeof(buffer));
        memset(data, 0, sizeof(data));
        memset(&cliPacket, 0, sizeof(cliPacket));
        dataLen = sizeof(data);
        int bytes = recvfrom(commandSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&sourceAddress), &sourceAddressLen);
        uint8_t packetType = buffer[0];
        if(bytes == CLIPacket_SIZE && packetType == e_CLI) {
            CLIPacket_deserialize(&cliPacket, buffer);
            rsaDecrypt(reinterpret_cast<uint8_t*>(data), &dataLen, reinterpret_cast<const uint8_t*>(cliPacket.data), sizeof(cliPacket.data));
            handleCommand(reinterpret_cast<const struct sockaddr*>(&sourceAddress), sourceAddressLen, data);
        } else if(bytes == KeyRequestPacket_SIZE && packetType == e_KeyRequest) {
            KeyResponsePacket keyResponsePacket;
            memset(&keyResponsePacket, 0, sizeof(keyResponsePacket));
            keyResponsePacket.packetType = e_KeyResponse;
            keyResponsePacket.success = 1;
            char* publicKey = NULL;
            size_t len = sizeof(keyResponsePacket.rsaPublicKey);
            getRSAPublicKey(&publicKey, &len);
            strncpy(keyResponsePacket.rsaPublicKey, publicKey, len);
            delete[] publicKey;

            KeyResponsePacket_serialize(buffer, &keyResponsePacket);
            int rc = sendto(commandSocket, buffer, KeyResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr*>(&sourceAddress), sourceAddressLen);
            if(rc < 0) {
                fprintf(stderr, "sendto() failed [%d]\n", errno);
            }
        }
    }

    return NULL;
}

void* listenerThread(void* a) {
    if(1) return NULL;
    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);
    int rc = 0;
    uint8_t buffer[1024];
    while(true) {
        memset(&sourceAddress, 0, sizeof(sourceAddress));
        memset(buffer, 0, sizeof(buffer));
        int bytes = recvfrom(controlSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&sourceAddress), &sourceAddressLen);

        
    }

    return NULL;
}

bool start()
{
    if(!initializeSecurity()) {
        return false;
    }

    memset(&listenerAddress, 0, sizeof(listenerAddress));
    controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if(controlSocket < 0) {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        cleanSecurity();
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
        cleanSecurity();
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
            cleanSecurity();
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
    cleanSecurity();
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