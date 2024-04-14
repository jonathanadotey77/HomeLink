#include <homelink_keyset.h>
#include <homelink_loginstatus.h>
#include <homelink_loginsystem.h>
#include <homelink_misc.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

bool verbose = false;

uint16_t listenerPort = 10000;
uint16_t serverStartPort = 10001;
uint16_t numPorts = 10;

int controlSocket = -1;
int commandSocket = -1;
int *dataSockets = NULL;

struct sockaddr_in6 listenerAddress;
struct sockaddr_in6 commandAddress;
struct sockaddr_in6 *dataAddresses;


pthread_t listenerThreadId = 0;
pthread_t commandThreadId = 0;

std::mutex serverLock;

volatile bool isStopped = false;

std::unordered_map<uint32_t, KeySet> clientKeys;
std::mutex clientKeysLock;

LoginSystem loginSystem;

void terminationHandler(int sig)
{
    fprintf(stderr, "Received signal: %s\n", strsignal(sig));

    isStopped = true;
}

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
            if (n >= 10)
            {
                numPorts = n;
            }
            else
            {
                fprintf(stderr, "Number of ports must be at least 10, dafaulting to 10\n");
            }
            i += 2;
        }
        else if (command == "--verbose")
        {
            verbose = true;
            i += 1;
        }
        else
        {
            std::cerr << "Invalid command '" << std::string(argv[i]) << "'" << std::endl;
            return false;
        }
    }

    return true;
}

std::vector<std::string> splitString(const std::string &s, char delim = ' ')
{
    std::vector<std::string> tokens;

    std::string temp;
    for (char c : s)
    {
        if (c == delim)
        {
            tokens.push_back(temp);
            temp.clear();
        }
        else
        {
            temp.push_back(c);
        }
    }

    if (!temp.empty())
    {
        tokens.push_back(temp);
    }

    return tokens;
}

void handleCLICommand(int commandSocket, const struct sockaddr *sourceAddress, socklen_t sourceAddressLen, const std::string &input)
{
    printf("%s\n", input.c_str());

    std::vector<std::string> tokens = splitString(input);

    std::string command = tokens[0];

    CLIPacket cliPacket;
    memset(&cliPacket, 0, sizeof(cliPacket));

    uint8_t buffer[sizeof(cliPacket)] = {0};
    CLIPacket_serialize(buffer, &cliPacket);

    int rc = sendto(commandSocket, buffer, sizeof(buffer), 0, sourceAddress, sourceAddressLen);
    if (rc < 0)
    {
        fprintf(stderr, "sendto() failed [%d]\n", errno);
    }
}

void *commandThread(void *)
{
    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);
    uint8_t buffer[1024];
    char data[257];
    CLIPacket cliPacket;
    size_t dataLen = sizeof(data) - 1;
    int rc = 0;
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));
    while (!isStopped)
    {

        fds[0].fd = commandSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 2000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() error [%d]\n", errno);
            break;
        }
        else if (rc == 0)
        {
            continue;
        }

        printf("Loop\n");
        memset(buffer, 0, sizeof(buffer));
        memset(data, 0, sizeof(data));
        memset(&cliPacket, 0, sizeof(cliPacket));
        dataLen = sizeof(data);

        rc = recvfrom(commandSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&sourceAddress), &sourceAddressLen);
        uint8_t packetType = buffer[0];
        if (rc == CLIPacket_SIZE && packetType == e_CLI)
        {
            CLIPacket_deserialize(&cliPacket, buffer);
            rsaDecrypt(reinterpret_cast<uint8_t *>(data), &dataLen, reinterpret_cast<const uint8_t *>(cliPacket.data), sizeof(cliPacket.data), NULL);
            data[sizeof(data) - 1] = '\0';
            handleCLICommand(commandSocket, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen, std::string(data));
        }
        else if (rc == KeyRequestPacket_SIZE && packetType == e_KeyRequest)
        {
            KeyResponsePacket keyResponsePacket;
            memset(&keyResponsePacket, 0, sizeof(keyResponsePacket));
            keyResponsePacket.packetType = e_KeyResponse;
            keyResponsePacket.success = 1;
            char publicKey[512] = {0};
            size_t len = sizeof(keyResponsePacket.rsaPublicKey);
            getRSAPublicKey(publicKey, &len);
            strncpy(keyResponsePacket.rsaPublicKey, publicKey, len);

            KeyResponsePacket_serialize(buffer, &keyResponsePacket);
            int rc = sendto(commandSocket, buffer, KeyResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen);
            if (rc < 0)
            {
                fprintf(stderr, "sendto() failed [%d]\n", errno);
            }
        }
    }

    return NULL;
}

void *listenerThread(void *)
{
    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);
    int rc = 0;
    uint8_t buffer[1024];
    while (!isStopped)
    {

        struct pollfd fds[1];
        fds[0].fd = controlSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() error [%d]\n", errno);
        }
        else if (rc == 0)
        {
            continue;
        }

        memset(&sourceAddress, 0, sizeof(sourceAddress));
        memset(buffer, 0, sizeof(buffer));
        rc = recvfrom(controlSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&sourceAddress), &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recfrom() failed [%d]\n", errno);
            continue;
        }
        else if (rc == 0)
        {
            fprintf(stderr, "recvfrom(): 0 bytes received\n");
            continue;
        }
        const uint8_t packetType = buffer[0];

        if (verbose)
        {
            char *ipAddress = new char[64];
            getIpv6Str(ipAddress, &sourceAddress.sin6_addr);
            printf("Received %d bytes from %s:%d \n", rc, ipAddress, ntohs(sourceAddress.sin6_port));
            printf("    Packet type: %d\n", static_cast<int>(packetType));
            delete[] ipAddress;
        }

        if (packetType == e_LoginRequest && rc == LoginRequestPacket_SIZE)
        {
            LoginRequestPacket loginRequestPacket;
            LoginRequestPacket_deserialize(&loginRequestPacket, buffer);

            uint8_t data[256] = {0};
            size_t dataLen = sizeof(data);
            rsaDecrypt(data, &dataLen, loginRequestPacket.data, sizeof(loginRequestPacket.data), NULL);
            const uint32_t connectionId = loginRequestPacket.connectionId;
            if (clientKeys.find(connectionId) == clientKeys.end())
            {
                continue;
            }
            uint32_t tag = ntohl(*(reinterpret_cast<const uint32_t *>(data)));
            const char *username = loginRequestPacket.username;
            const char *password = reinterpret_cast<const char *>(data + 32);

            if (clientKeys[connectionId].checkTag(tag) && loginSystem.tryLogin(username, reinterpret_cast<const char *>(password)) == e_LoginSuccess)
            {
                LoginResponsePacket loginResponsePacket;
                loginResponsePacket.packetType = e_LoginResponse;
                loginResponsePacket.status = 1;
                const char *sessionToken = clientKeys[connectionId].newSessionKey();
                size_t outLen = sizeof(loginResponsePacket.sessionKey);

                rsaEncrypt(loginResponsePacket.sessionKey, &outLen, reinterpret_cast<const uint8_t *>(sessionToken), strlen(sessionToken)+1, clientKeys[connectionId].getPublicKey());

                memset(buffer, 0, sizeof(buffer));
                LoginResponsePacket_serialize(buffer, &loginResponsePacket);

                rc = sendto(controlSocket, buffer, LoginResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen);
                if (rc < 0)
                {
                    fprintf(stderr, "sendto() failed [%d]\n", errno);
                }

                memset(&loginResponsePacket, 0, sizeof(loginResponsePacket));
            }

            memset(&loginRequestPacket, 0, sizeof(loginRequestPacket));
        }
        else if (packetType == e_RegisterRequest)
        {
            RegisterRequestPacket registerRequestPacket;
            RegisterRequestPacket_deserialize(&registerRequestPacket, buffer);

            if (verbose)
            {
                printf("Register request received wuth username=%s\n", registerRequestPacket.username);
            }

            uint8_t data[256] = {0};
            size_t dataLen = sizeof(data);
            bool decrypted = rsaDecrypt(data, &dataLen, registerRequestPacket.data, sizeof(registerRequestPacket.data), NULL);

            if (!decrypted)
            {
                if (verbose)
                {
                    printf("Decryption failed\n");
                }
                continue;
            }

            const uint32_t connectionId = registerRequestPacket.connectionId;
            if (clientKeys.find(connectionId) == clientKeys.end())
            {
                printf("Invalid connectionId {%u}\n", connectionId);
                continue;
            }
            const char *username = registerRequestPacket.username;
            const char *password = reinterpret_cast<const char *>(data + 32);

            LoginStatus status = loginSystem.registerUser(username, password);

            if (verbose)
            {
                printf("Replying with status %d\n", static_cast<int>(status));
            }
            RegisterResponsePacket registerResponsePacket;
            registerResponsePacket.packetType = e_RegisterResponse;
            registerResponsePacket.status = static_cast<uint8_t>(status);

            memset(buffer, 0, sizeof(buffer));
            RegisterResponsePacket_serialize(buffer, &registerResponsePacket);

            rc = sendto(controlSocket, buffer, RegisterResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen);
            if (rc < 0)
            {
                fprintf(stderr, "sendto() failed [%d]\n", errno);
            }
        }
        else if (packetType == e_KeyRequest && rc == KeyRequestPacket_SIZE)
        {

            KeyRequestPacket keyRequestPacket;
            KeyRequestPacket_deserialize(&keyRequestPacket, buffer);
            if (verbose)
            {
                printf("Connection id: %d\n", keyRequestPacket.connectionId);
            }
            {
                int idx = sizeof(keyRequestPacket.rsaPublicKey) - 1;
                bool foundNullCharacter = false;
                while (idx >= 0)
                {
                    if (keyRequestPacket.rsaPublicKey[idx] == '\0')
                    {
                        foundNullCharacter = true;
                        break;
                    }
                    else
                    {
                        idx -= 1;
                    }
                }

                if (!foundNullCharacter)
                {
                    if (verbose)
                    {
                        printf("Invalid RSA key data\n");
                        continue;
                    }
                }
            }
            
            bool success = clientKeys.insert({keyRequestPacket.connectionId, KeySet(keyRequestPacket.rsaPublicKey, strlen(keyRequestPacket.rsaPublicKey))}).second;

            if (verbose)
            {
                printf("Key request %s\n", success ? "succeeded" : "failed");
            }

            KeyResponsePacket keyResponsePacket;
            memset(&keyResponsePacket, 0, sizeof(keyResponsePacket));
            keyResponsePacket.packetType = e_KeyResponse;
            keyResponsePacket.success = success ? 1 : 0;

            char publicKey[512] = {0};
            size_t len = sizeof(keyResponsePacket.rsaPublicKey);
            getRSAPublicKey(publicKey, &len);
            strncpy(keyResponsePacket.rsaPublicKey, publicKey, len);

            KeyResponsePacket_serialize(buffer, &keyResponsePacket);
            int rc = sendto(controlSocket, buffer, KeyResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen);
            if (rc < 0)
            {
                fprintf(stderr, "sendto() failed [%d]\n", errno);
            }
        }
    }

    return NULL;
}

bool start()
{

    if (!loginSystem.start())
    {
        fprintf(stderr, "Failed to start login system\n");
        return false;
    }

    if (!initializeSecurity())
    {
        return false;
    }

    memset(&listenerAddress, 0, sizeof(listenerAddress));
    controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (controlSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        cleanSecurity();
        return false;
    }

    commandSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (commandSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return NULL;
    }

    dataSockets = new int[numPorts];
    dataAddresses = new struct sockaddr_in6[numPorts];

    listenerAddress.sin6_family = AF_INET6;
    listenerAddress.sin6_addr = in6addr_any;
    listenerAddress.sin6_port = htons(listenerPort);
    listenerAddress.sin6_flowinfo = 0;
    listenerAddress.sin6_scope_id = 0;

    commandAddress.sin6_family = AF_INET6;
    commandAddress.sin6_addr = parseIpAddress("127.0.0.1");
    commandAddress.sin6_port = htons(45000);
    commandAddress.sin6_flowinfo = 0;
    commandAddress.sin6_scope_id = 0;

    if (bind(controlSocket, reinterpret_cast<const sockaddr *>(&listenerAddress), sizeof(listenerAddress)) < 0)
    {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        cleanSecurity();
        return false;
    }

    if (bind(commandSocket, reinterpret_cast<const struct sockaddr *>(&commandAddress), sizeof(commandAddress)) < 0)
    {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        return NULL;
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

    signal(SIGTSTP, terminationHandler);
    signal(SIGINT, terminationHandler);
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

    close(commandSocket);

    loginSystem.stop();

    cleanSecurity();
}

int main(int argc, char *argv[])
{
    if (!parseArgs(argc, argv))
    {
        printf("Arg parse failed\n");
        return 1;
    }

    if (!start())
    {
        printf("Start failed\n");
        return 1;
    }

    std::cout << "HomeLink server listening on port " << listenerPort << std::endl;

    pthread_join(commandThreadId, NULL);
    pthread_join(listenerThreadId, NULL);

    stop();

    std::cout << "Homelink server stopped" << std::endl;

    return 0;
}