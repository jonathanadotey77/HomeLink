#include <homelink_filequeue.h>
#include <homelink_keyset.h>
#include <homelink_loginstatus.h>
#include <homelink_loginsystem.h>
#include <homelink_misc.h>
#include <homelink_net.h>
#include <homelink_packet.h>
#include <homelink_security.h>

#include <arpa/inet.h>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

bool verbose = false;

uint16_t controlPort = 10000;
uint16_t dataPort = 10001;

int controlSocket = -1;
int commandSocket = -1;
int dataSocket = -1;

struct sockaddr_in6 controlAddress;
struct sockaddr_in6 commandAddress;
struct sockaddr_in6 dataAddress;

pthread_t controlThreadId = 0;
pthread_t commandThreadId = 0;
pthread_t dataThreadId = 0;

std::mutex serverLock;

volatile bool isStopped = false;

std::unordered_map<uint32_t, KeySet> clientKeys;
std::mutex clientKeysLock;

std::unordered_set<pthread_t> clientThreads;
std::mutex clientThreadsLock;

FileQueue fileQueue;
LoginSystem loginSystem;

typedef struct ClientThreadArgs
{
    int sd;
    struct sockaddr_in6 sourceAddress;
} ClientThreadArgs;

static const std::string TEMP_FILES_PATH = std::string(std::getenv("HOMELINK_ROOT")) + "/temp_files";

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

        if (command == "--control-port")
        {
            int p = atoi(argv[i + 1]);
            if (p > UINT16_MAX || p <= 0)
            {
                std::cerr << "Invalid control port" << std::endl;
                return false;
            }

            controlPort = static_cast<uint16_t>(p);
            i += 2;
        }
        else if (command == "--data-port")
        {
            int p = atoi(argv[i + 1]);
            if (p > UINT16_MAX || p <= 0)
            {
                std::cerr << "Invalid data port" << std::endl;
                return false;
            }

            dataPort = static_cast<uint16_t>(p);
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

bool validateClient(uint32_t connectionId, const uint8_t *encryptedSessionKey, size_t encryptedSessionKeyLen)
{
    if (verbose)
    {
        printf("Validating client {connectionId=%u}\n", connectionId);
    }
    bool success = false;
    char sessionKey[256];
    memset(sessionKey, 0, sizeof(sessionKey));
    size_t len = sizeof(sessionKey);

    clientKeysLock.lock();
    if (rsaDecrypt(reinterpret_cast<uint8_t *>(sessionKey), &len, encryptedSessionKey, encryptedSessionKeyLen, NULL))
    {
        if (clientKeys.find(connectionId) == clientKeys.end())
        {
            if (verbose)
            {
                printf("Connection ID not found\n");
            }
        }
        else if (clientKeys[connectionId].validSessionKey(sessionKey))
        {
            if (verbose)
            {
                printf("Validation successful\n");
            }
            success = true;
        }
    }
    else
    {
        if (verbose)
        {
            printf("Could not decrypt session key\n");
        }
    }
    clientKeysLock.unlock();
    memset(sessionKey, 0, sizeof(sessionKey));

    return success;
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
        else if (rc == 9 && packetType == 254)
        {
            pthread_t *threadPtr = reinterpret_cast<pthread_t *>(buffer + 1);
            clientThreadsLock.lock();
            clientThreads.erase(*threadPtr);
            clientThreadsLock.unlock();
            pthread_join(*threadPtr, NULL);
        }
    }

    return NULL;
}

void *controlThread(void *)
{
    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);
    int rc = 0;
    uint8_t buffer[1024];
    struct pollfd fds[1];
    while (!isStopped)
    {

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

            if (verbose)
            {
                printf("Login request received with {hostId, serviceID} = {%s, %s}\n", loginRequestPacket.hostId, loginRequestPacket.serviceId);
            }
            const uint32_t connectionId = loginRequestPacket.connectionId;
            clientKeysLock.lock();
            if (clientKeys.find(connectionId) == clientKeys.end())
            {
                if (verbose)
                {
                    printf("Invalid connectionId {%u}\n", connectionId);
                }
                continue;
            }
            uint32_t tag = ntohl(*(reinterpret_cast<const uint32_t *>(data)));
            const char *hostId = loginRequestPacket.hostId;
            const char *serviceId = loginRequestPacket.serviceId;
            const char *password = reinterpret_cast<const char *>(data + 32);

            if (clientKeys[connectionId].checkTag(tag) && loginSystem.tryLogin(hostId, serviceId, reinterpret_cast<const char *>(password)) == e_LoginSuccess)
            {
                if (verbose)
                {
                    printf("Login success\n");
                }

                clientKeys[connectionId].setUser(hostId, serviceId);

                LoginResponsePacket loginResponsePacket;
                loginResponsePacket.packetType = e_LoginResponse;
                loginResponsePacket.status = 1;
                const char *sessionToken = clientKeys[connectionId].newSessionKey();
                size_t outLen = sizeof(loginResponsePacket.sessionKey);

                rsaEncrypt(loginResponsePacket.sessionKey, &outLen, reinterpret_cast<const uint8_t *>(sessionToken), strlen(sessionToken) + 1, clientKeys[connectionId].getPublicKey());

                memset(buffer, 0, sizeof(buffer));
                LoginResponsePacket_serialize(buffer, &loginResponsePacket);

                rc = sendto(controlSocket, buffer, LoginResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen);
                if (rc < 0)
                {
                    fprintf(stderr, "sendto() failed [%d]\n", errno);
                }

                memset(&loginResponsePacket, 0, sizeof(loginResponsePacket));
            }
            clientKeysLock.unlock();

            memset(&loginRequestPacket, 0, sizeof(loginRequestPacket));
        }
        else if (packetType == e_RegisterRequest)
        {
            RegisterRequestPacket registerRequestPacket;
            RegisterRequestPacket_deserialize(&registerRequestPacket, buffer);

            if (verbose)
            {
                printf("Register request received with {hostId, serviceID} = {%s, %s}\n", registerRequestPacket.hostId, registerRequestPacket.serviceId);
            }

            bool valid = true;

            for (char *c = registerRequestPacket.hostId; *c != '\0'; ++c)
            {
                if (*c == '/')
                {
                    if (verbose)
                    {
                        printf("Invalid hostId");
                    }

                    valid = false;
                }
            }

            for (char *c = registerRequestPacket.serviceId; *c != '\0'; ++c)
            {
                if (*c == '/')
                {
                    if (verbose)
                    {
                        printf("Invalid serviceId");
                    }

                    valid = false;
                }
            }

            if (!valid)
            {
                memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
                continue;
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

                memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
                continue;
            }

            const uint32_t connectionId = registerRequestPacket.connectionId;
            if (clientKeys.find(connectionId) == clientKeys.end())
            {
                printf("Invalid connectionId {%u}\n", connectionId);
                memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
                continue;
            }
            const char *hostId = registerRequestPacket.hostId;
            const char *serviceId = registerRequestPacket.serviceId;
            const char *password = reinterpret_cast<const char *>(data + 32);

            LoginStatus status = loginSystem.registerUser(hostId, serviceId, password);

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

            memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
            memset(&registerResponsePacket, 0, sizeof(registerResponsePacket));
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

            rsaEncrypt(keyResponsePacket.aesKey, &len, clientKeys[keyRequestPacket.connectionId].getAesKey(), AES_KEY_LEN / 8, keyRequestPacket.rsaPublicKey);

            KeyResponsePacket_serialize(buffer, &keyResponsePacket);
            int rc = sendto(controlSocket, buffer, KeyResponsePacket_SIZE, 0, reinterpret_cast<const struct sockaddr *>(&sourceAddress), sourceAddressLen);
            if (rc < 0)
            {
                fprintf(stderr, "sendto() failed [%d]\n", errno);
            }
        }
        else if (packetType == e_Logout)
        {
            LogoutPacket logoutPacket;
            LogoutPacket_deserialize(&logoutPacket, buffer);

            if (verbose)
            {
                printf("Logout packet received {%u}\n", logoutPacket.connectionId);
            }

            if (validateClient(logoutPacket.connectionId, logoutPacket.sessionKey, sizeof(logoutPacket.sessionKey)))
            {
                clientKeys.erase(logoutPacket.connectionId);
            }

            memset(&logoutPacket, 0, sizeof(logoutPacket));
        }
    }

    return NULL;
}

void *clientThread(void *a)
{
    ClientThreadArgs *args = reinterpret_cast<ClientThreadArgs *>(a);

    int sd = args->sd;
    struct sockaddr_in6 sourceAddress = args->sourceAddress;

    delete args;

    uint8_t commandBuffer[CommandPacket_SIZE];
    const size_t commandBufferLen = sizeof(commandBuffer);
    size_t n = 0;
    uint8_t* aesKey = NULL;

    CommandPacket commandPacket;

    if (verbose)
    {
        char *ipAddress = new char[64];
        getIpv6Str(ipAddress, &sourceAddress.sin6_addr);
        printf("Received TCP connection from %s:%d \n", ipAddress, ntohs(sourceAddress.sin6_port));
        delete[] ipAddress;
    }

    while (!isStopped)
    {
        memset(&commandPacket, 0, sizeof(commandPacket));
        memset(&commandBuffer, 0, sizeof(commandBuffer));
        n = 0;

        for (int i = 0; i < 5 && n < commandBufferLen; ++i)
        {
            n += recv(sd, commandBuffer, commandBufferLen - n, 0);
        }

        if (n != commandBufferLen)
        {
            break;
        }

        CommandPacket_deserialize(&commandPacket, commandBuffer);

        if (commandPacket.packetType != e_Command)
        {
            break;
        }

        if (!validateClient(commandPacket.connectionId, commandPacket.sessionToken, sizeof(commandPacket.sessionToken)))
        {
            if (verbose)
            {
                printf("Client validation failed\n");
            }

            break;
        }

        clientKeysLock.lock();
        const KeySet &info = clientKeys[commandPacket.connectionId];
        std::string hostId = info.getHostId();
        std::string serviceId = info.getServiceId();
        aesKey = info.getAesKey();
        clientKeysLock.unlock();

        char commandStr[256] = {0};
        size_t commandStrLen = sizeof(commandStr);
        if (!rsaDecrypt(reinterpret_cast<uint8_t *>(commandStr), &commandStrLen, commandPacket.data, sizeof(commandPacket.data), NULL))
        {
            if (verbose)
            {
                printf("Command decryption failed\n");
            }

            break;
        }

        std::vector<std::string> tokens = splitString(std::string(commandStr + 32), ' ');

        if (tokens.empty())
        {
            break;
        }

        const std::string &command = tokens[0];

        if(verbose) {
            printf("Recevied command: %s\n", commandStr + 32);
        }

        if (command == "READ_FILE")
        {
            std::string tempFilePath = fileQueue.nextFile(hostId, serviceId);
            if(tempFilePath.empty()) {
                break;
            }
            std::string tempFilename = splitString(tempFilePath, '/').back();
            bool status = false;
            uint32_t i = 0;
            for(; i < tempFilename.size(); ++i) {
                if(tempFilename[i] == '.') {
                    ++i;
                    status = true;
                    break;
                }   
            }

            if(!status) {
                break;
            }
            
            status = sendFile(sd, tempFilePath.c_str(), tempFilename.c_str() + i, aesKey);

            if(status) {
                if(verbose) {
                    printf("File read succeeded\n");
                }

                if(verbose) {
                    printf("Clearing %s from file queue {%s | %s}", tempFilename.c_str(), hostId.c_str(), serviceId.c_str());
                }
                fileQueue.pullFile(tempFilePath);
            } else {
                if(verbose) {
                    printf("Failed to send file\n");
                }
            }
        }
        else if (command == "WRITE_FILE")
        {
            if (tokens.size() != 5)
            {
                break;
            }
            const std::string destinationHostId = tokens[1];
            const std::string destinationServiceId = tokens[2];
            const std::string &filePath = tokens[3];

            if (filePath.empty())
            {
                break;
            }

            std::string tempFileFolder = TEMP_FILES_PATH + "/" + destinationHostId + "/" + destinationServiceId + "/";
            std::string tempFilePrefix = tempFileFolder;


            bool validName = true;
            for (char c : getTimestamp())
            {
                tempFilePrefix.push_back(c);
            }
            tempFilePrefix.push_back('.');
            std::string tempFilePath = tempFilePrefix;

            for (char c : filePath)
            {
                if (c == '/')
                {
                    tempFilePath.push_back('+');
                }
                else if (c == '+')
                {
                    validName = false;
                    break;
                }
                else
                {
                    tempFilePath.push_back(c);
                }
            }

            if (!validName)
            {
                break;
            }

            if(verbose) {
                printf("Writing to %s\n", tempFilePath.c_str());
            }

            fs::create_directories(tempFileFolder);
            bool status = recvFile(sd, tempFilePrefix.c_str(), aesKey, true);

            if (status)
            {
                if(verbose) {
                    printf("File received successfully\n");
                }

                fileQueue.pushFile(destinationHostId, destinationServiceId, tempFilePath);
            } else {
                if(verbose) {
                    printf("Failed to received file\n");
                }
            }
        }

        break;
    }

    if(aesKey != NULL) {
        memset(aesKey, 0, 32);
        delete[] aesKey;
        aesKey = NULL;
    }

    close(sd);

    // Join this thread
    sd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sd < 0)
    {
        return NULL;
    }

    uint8_t buffer[9] = {0};
    buffer[0] = 254;
    *(reinterpret_cast<pthread_t *>(buffer + 1)) = pthread_self();
    int rc = sendto(sd, buffer, sizeof(buffer), 0, reinterpret_cast<const struct sockaddr *>(&commandAddress), sizeof(commandAddress));
    if(rc < 0) {
        fprintf(stderr, "sendto() failed [%d]\n", errno);
    }

    return NULL;
}

void *dataThread(void *)
{

    if (listen(dataSocket, 5) < 0)
    {
        fprintf(stderr, "listen() failed [%d]\n", errno);
        return NULL;
    }

    struct pollfd fds[1];
    int rc = 0;

    struct sockaddr_in6 sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);

    while (!isStopped)
    {
        memset(&sourceAddress, 0, sizeof(sourceAddress));
        sourceAddressLen = sizeof(sourceAddress);

        fds[0].fd = dataSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        rc = poll(fds, 1, 2000);

        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
            continue;
        }
        else if (rc == 0)
        {
            continue;
        }

        int sd = accept(dataSocket, reinterpret_cast<struct sockaddr *>(&sourceAddress), &sourceAddressLen);
        if (sd < 0)
        {
            fprintf(stderr, "accept() failed [%d]\n", errno);
        }
        else
        {
        }
        ClientThreadArgs *args = new ClientThreadArgs;
        args->sd = sd;
        args->sourceAddress = sourceAddress;

        pthread_t threadId = 0;
        pthread_create(&threadId, NULL, clientThread, args);

        clientThreadsLock.lock();
        clientThreads.insert(threadId);
        clientThreadsLock.unlock();
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

    memset(&controlAddress, 0, sizeof(controlAddress));
    controlSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (controlSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        cleanSecurity();
        return false;
    }

    dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (dataSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        close(controlSocket);
        cleanSecurity();
        return false;
    }

    struct linger ling;
    ling.l_onoff = 0;
    ling.l_linger = 0;

    int optval = 1;
    setsockopt(dataSocket, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    setsockopt(dataSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(dataSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    commandSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (commandSocket < 0)
    {
        close(controlSocket);
        close(dataSocket);
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return NULL;
    }

    controlAddress.sin6_family = AF_INET6;
    controlAddress.sin6_addr = in6addr_any;
    controlAddress.sin6_port = htons(controlPort);
    controlAddress.sin6_flowinfo = 0;
    controlAddress.sin6_scope_id = 0;

    dataAddress = controlAddress;
    dataAddress.sin6_port = htons(dataPort);

    commandAddress.sin6_family = AF_INET6;
    commandAddress.sin6_addr = parseIpAddress("127.0.0.1");
    commandAddress.sin6_port = htons(45000);
    commandAddress.sin6_flowinfo = 0;
    commandAddress.sin6_scope_id = 0;

    if (bind(controlSocket, reinterpret_cast<const sockaddr *>(&controlAddress), sizeof(controlAddress)) < 0)
    {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        cleanSecurity();
        return false;
    }

    if (bind(commandSocket, reinterpret_cast<const struct sockaddr *>(&commandAddress), sizeof(commandAddress)) < 0)
    {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        close(controlSocket);
        cleanSecurity();
        return NULL;
    }

    if (bind(dataSocket, reinterpret_cast<const struct sockaddr *>(&dataAddress), sizeof(dataAddress)) < 0)
    {
        fprintf(stderr, "bind()  failed [%d]\n", errno);
        close(controlSocket);
        close(commandSocket);
        cleanSecurity();
        return NULL;
    }

    signal(SIGTSTP, terminationHandler);
    signal(SIGINT, terminationHandler);
    pthread_create(&commandThreadId, NULL, commandThread, NULL);
    pthread_create(&controlThreadId, NULL, controlThread, NULL);
    pthread_create(&dataThreadId, NULL, dataThread, NULL);

    return true;
}

void stop()
{
    close(controlSocket);
    close(dataSocket);
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

    std::cout << "HomeLink server listening on port " << controlPort << std::endl;

    pthread_join(commandThreadId, NULL);
    pthread_join(controlThreadId, NULL);
    pthread_join(dataThreadId, NULL);

    clientThreadsLock.lock();
    for (pthread_t tid : clientThreads)
    {
        pthread_join(tid, NULL);
    }
    clientThreadsLock.unlock();

    stop();

    std::cout << "Homelink server stopped" << std::endl;

    return 0;
}
