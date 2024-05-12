#include <homelink_asyncthreadpool.h>
#include <homelink_filequeue.h>
#include <homelink_keyset.h>
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
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

bool verbose = false;

uint16_t serverPort = 10000;

int serverSocket = -1;

struct sockaddr_in6 serverAddress;

pthread_t dataThreadId = 0;

std::mutex serverLock;

volatile bool isStopped = false;

std::unordered_map<uint32_t, KeySet> clientKeys;
std::mutex clientKeysLock;

AsyncThreadPool *asyncThreadPool = NULL;
FileQueue *fileQueue = NULL;
LoginSystem *loginSystem = NULL;

typedef struct ClientThreadArgs
{
    int sd;
    struct sockaddr_in6 sourceAddress;
} ClientThreadArgs;

static const std::string TEMP_FILES_PATH =
    std::string(std::getenv("HOMELINK_ROOT")) + "/temp_files";

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

        if (command == "--data-port")
        {
            int p = atoi(argv[i + 1]);
            if (p > UINT16_MAX || p <= 0)
            {
                std::cerr << "Invalid data port" << std::endl;
                return false;
            }

            serverPort = static_cast<uint16_t>(p);
            i += 2;
        }
        else if (command == "--verbose")
        {
            verbose = true;
            i += 1;
        }
        else
        {
            std::cerr << "Invalid command '" << std::string(argv[i]) << "'"
                      << std::endl;
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

bool validateClient(uint32_t connectionId, uint8_t *encryptedSessionKey)
{
    if (verbose)
    {
        printf("Validating client {connectionId=%u}\n", connectionId);
    }
    bool success = false;
    char sessionKey[48];
    memset(sessionKey, 0, sizeof(sessionKey));

    clientKeysLock.lock();
    if (clientKeys.find(connectionId) == clientKeys.end())
    {
        if (verbose)
        {
            printf("Connection ID not found\n");
        }
    }
    else
    {
        uint8_t *aesKey = clientKeys[connectionId].getAesKey();
        success = decryptSessionKey(sessionKey, encryptedSessionKey, aesKey);
        memset(aesKey, 0, AES_KEY_SIZE / 8);
        delete[] aesKey;
        aesKey = NULL;
        if (!success)
        {
            if (verbose)
            {
                printf("Could not decrypt session key\n");
            }
        }
        else
        {
            success = clientKeys[connectionId].validSessionKey(sessionKey);
            if (success)
            {
                if (verbose)
                {
                    printf("Validation successful\n");
                }
            }
            else
            {
                printf("Invalid: %s\n", sessionKey);
            }
        }
    }
    clientKeysLock.unlock();
    memset(sessionKey, 0, sizeof(sessionKey));

    return success;
}

void handleKeyRequest(int sd, const KeyRequestPacket *keyRequestPacket)
{
    {
        int idx = sizeof(keyRequestPacket->rsaPublicKey) - 1;
        bool foundNullCharacter = false;
        while (idx >= 0)
        {
            if (keyRequestPacket->rsaPublicKey[idx] == '\0')
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
                return;
            }
        }
    }

    bool success = clientKeys.insert({keyRequestPacket->connectionId, KeySet(keyRequestPacket->rsaPublicKey, strlen(keyRequestPacket->rsaPublicKey))}).second;

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

    uint8_t *aesKey = clientKeys[keyRequestPacket->connectionId].getAesKey();
    rsaEncrypt(keyResponsePacket.aesKey, &len, aesKey, AES_KEY_SIZE / 8, keyRequestPacket->rsaPublicKey);
    memset(aesKey, 0, AES_KEY_SIZE / 8);
    delete[] aesKey;

    uint8_t buffer[KeyResponsePacket_SIZE];

    KeyResponsePacket_serialize(buffer, &keyResponsePacket);
    bool status = sendBufferTcp(sd, buffer, KeyResponsePacket_SIZE);
    if (!status)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
    }
}

void handleRegisterRequest(int sd, const RegisterRequestPacket *registerRequestPacket)
{
    if (verbose)
    {
        if (registerRequestPacket->registrationType == e_HostRegistration)
        {
            printf("Register request received with {hostId} = {%s}\n", registerRequestPacket->hostId);
        }
        else if (registerRequestPacket->registrationType == e_ServiceRegistration)
        {
            printf("Register request received with {hostId, serviceID} = {%s, %s}\n", registerRequestPacket->hostId, registerRequestPacket->serviceId);
        }
    }

    if (registerRequestPacket->registrationType != e_HostRegistration && registerRequestPacket->registrationType != e_ServiceRegistration)
    {
        if (verbose)
        {
            printf("Register request received with invalid registration type\n");
        }

        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
        return;
    }

    bool valid = true;

    for (const char *c = registerRequestPacket->hostId; *c != '\0'; ++c)
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

    for (const char *c = registerRequestPacket->serviceId; *c != '\0'; ++c)
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
        return;
    }

    uint8_t data[256] = {0};
    size_t dataLen = sizeof(data);
    bool decrypted = rsaDecrypt(data, &dataLen, registerRequestPacket->data,
                                sizeof(registerRequestPacket->data), NULL);

    if (!decrypted)
    {
        if (verbose)
        {
            printf("Decryption failed\n");
        }

        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
        memset(data, 0, sizeof(data));
        return;
    }

    RegisterStatus status = e_RegisterFailed;

    const char *hostId = registerRequestPacket->hostId;
    char *hostKey = reinterpret_cast<char *>(data + 32);
    hostKey[65] = '\0';
    if (registerRequestPacket->registrationType == e_HostRegistration)
    {
        status = loginSystem->registerHost(hostId, hostKey);
    }
    else if (registerRequestPacket->registrationType ==
             e_ServiceRegistration)
    {
        const char *serviceId = registerRequestPacket->serviceId;
        char *password = reinterpret_cast<char *>(data + 97);
        password[65] = '\0';

        status =
            loginSystem->registerService(hostId, serviceId, hostKey, password);
    }
    else
    {
        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
        memset(data, 0, sizeof(data));
        return;
    }

    if (verbose)
    {
        printf("Replying with status %d\n", static_cast<int>(status));
    }
    RegisterResponsePacket registerResponsePacket;
    registerResponsePacket.packetType = e_RegisterResponse;
    registerResponsePacket.status = static_cast<uint8_t>(status);

    uint8_t buffer[KeyResponsePacket_SIZE];
    RegisterResponsePacket_serialize(buffer, &registerResponsePacket);

    bool success = sendBufferTcp(sd, buffer, KeyResponsePacket_SIZE);
    if (!success)
    {
        fprintf(stderr, "sendBufferTcp() failed\n");
    }

    memset(&registerResponsePacket, 0, sizeof(registerResponsePacket));
    memset(data, 0, sizeof(data));
}

void handleLoginRequest(int sd, const LoginRequestPacket *loginRequestPacket)
{
    uint8_t data[256] = {0};
    size_t dataLen = sizeof(data);
    rsaDecrypt(data, &dataLen, loginRequestPacket->data,
               sizeof(loginRequestPacket->data), NULL);

    if (verbose)
    {
        printf("Login request received with {hostId, serviceID} = {%s, %s}\n",
               loginRequestPacket->hostId, loginRequestPacket->serviceId);
    }
    const uint32_t connectionId = loginRequestPacket->connectionId;
    clientKeysLock.lock();
    if (clientKeys.find(connectionId) == clientKeys.end())
    {
        if (verbose)
        {
            printf("Invalid connectionId {%u}\n", connectionId);
        }
        return;
    }
    uint64_t tag = ntohl(*(reinterpret_cast<const uint64_t *>(data)));
    const char *hostId = loginRequestPacket->hostId;
    const char *serviceId = loginRequestPacket->serviceId;
    const char *hostKey = reinterpret_cast<const char *>(data + 32);
    const char *password = reinterpret_cast<const char *>(data + 97);

    if (clientKeys[connectionId].checkTag(tag))
    {
        LoginStatus status = loginSystem->tryLogin(hostId, serviceId, hostKey, password);
        if (verbose)
        {
            if (status == e_LoginSuccess)
            {
                printf("Login success\n");
            }
            else if (status == e_LoginFailed)
            {
                printf("Login failed\n");
            }
            else if (status == e_NoSuchService)
            {
                printf("No such service '%s'\n", serviceId);
            }
        }

        LoginResponsePacket loginResponsePacket;
        loginResponsePacket.packetType = e_LoginResponse;
        loginResponsePacket.status = status;

        if (status == e_LoginSuccess)
        {
            clientKeys[connectionId].setUser(hostId, serviceId);

            const char *sessionKey = clientKeys[connectionId].newSessionKey();

            uint8_t *aesKey = clientKeys[connectionId].getAesKey();
            bool success = encryptSessionKey(loginResponsePacket.sessionKey, sessionKey, aesKey);
            memset(aesKey, 0, AES_KEY_SIZE / 8);
            delete[] aesKey;
            if (!success)
            {
                clientKeysLock.unlock();
                fprintf(stderr, "encryptSessionKey() failed\n");
                return;
            }
        }
        else
        {
            randomBytes(loginResponsePacket.sessionKey, sizeof(loginResponsePacket.sessionKey));
        }

        uint8_t buffer[LoginResponsePacket_SIZE];
        LoginResponsePacket_serialize(buffer, &loginResponsePacket);

        bool success = sendBufferTcp(sd, buffer, LoginResponsePacket_SIZE);
        if (!success)
        {
            fprintf(stderr, "sendBufferTcp() failed\n");
        }

        memset(&loginResponsePacket, 0, sizeof(loginResponsePacket));
    }

    clientKeysLock.unlock();
}

void handleLogout(LogoutPacket *logoutPacket)
{
    if (verbose)
    {
        printf("Logout packet received {%u}\n", logoutPacket->connectionId);
    }

    if (validateClient(logoutPacket->connectionId, logoutPacket->sessionKey))
    {
        clientKeysLock.lock();
        if (verbose)
        {
            const std::string &hostId = clientKeys[logoutPacket->connectionId].getHostId();
            const std::string &serviceId = clientKeys[logoutPacket->connectionId].getServiceId();
            printf("Logout success {%s | %s}\n", hostId.c_str(), serviceId.c_str());

            asyncThreadPool->removeService(hostId, serviceId, e_AnyEvent);
        }
        clientKeys.erase(logoutPacket->connectionId);
        clientKeysLock.unlock();
    }
}

void handleReadFileCommand(int sd, const std::string &hostId, const std::string &serviceId, const uint8_t *aesKey)
{
    std::string tempFilePath = fileQueue->nextFile(hostId, serviceId);
    if (tempFilePath.empty())
    {
        uint8_t buffer[1] = {0};
        if (!sendBufferTcp(sd, buffer, 1))
        {
            fprintf(stderr, "Could not send initial response for READ_FILE\n");
        }
        return;
    }
    else
    {
        uint8_t buffer[1] = {1};
        if (!sendBufferTcp(sd, buffer, 1))
        {
            fprintf(stderr, "Could not send initial response for READ_FILE\n");
            return;
        }
    }
    std::string tempFilename = splitString(tempFilePath, '/').back();
    bool status = false;
    uint32_t i = 0;
    int32_t tag = 0;
    int start = 0;
    for (; i < tempFilename.size(); ++i)
    {
        if (tempFilename[i] == '|')
        {
            start = i + 1;

            continue;
        }

        if (tempFilename[i] == '.')
        {
            tempFilename[i] = '\0';
            tag = atoll(tempFilename.c_str() + start);
            ++i;
            status = true;
            break;
        }
    }

    if (!status)
    {
        return;
    }

    status = sendFile(sd, tempFilePath.c_str(), tempFilename.c_str() + i, aesKey, tag);

    if (status)
    {
        if (verbose)
        {
            printf("File read succeeded\n");
        }

        if (verbose)
        {
            printf("Clearing %s from file queue {%s | %s}\n",
                   tempFilename.c_str(), hostId.c_str(), serviceId.c_str());
        }
        fileQueue->pullFile(tempFilePath);
    }
    else
    {
        if (verbose)
        {
            printf("Failed to send file\n");
        }
    }
}

void *clientThread(void *a)
{
    ClientThreadArgs *args = reinterpret_cast<ClientThreadArgs *>(a);

    int sd = args->sd;
    struct sockaddr_in6 sourceAddress = args->sourceAddress;

    delete args;

    CommandPacket commandPacket;

    char sourceAddressStr[64];

    if (verbose)
    {
        getIpv6Str(sourceAddressStr, &sourceAddress.sin6_addr);
    }

    uint8_t buffer[1024];
    uint8_t *aesKey = NULL;

    // We check the first byte, which contains the packet type
    bool status = recvBufferTcp(sd, buffer, 1);
    if (!status)
    {
        fprintf(stderr, "recvBufferTcp() failed\n");
        close(sd);
        return NULL;
    }

    HomeLinkPacketType packetType = static_cast<HomeLinkPacketType>(buffer[0]);

    const bool isCommandPacket = packetType == e_Command;
    if (packetType == e_KeyRequest)
    {
        status = recvBufferTcp(sd, buffer + 1, KeyRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return NULL;
        }

        KeyRequestPacket keyRequestPacket;
        KeyRequestPacket_deserialize(&keyRequestPacket, buffer);

        if (verbose)
        {
            printf("Key request received from %s with connection id {%d}\n", sourceAddressStr, keyRequestPacket.connectionId);
        }

        handleKeyRequest(sd, &keyRequestPacket);
    }
    else if (packetType == e_RegisterRequest)
    {
        status = recvBufferTcp(sd, buffer + 1, RegisterRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return NULL;
        }

        RegisterRequestPacket registerRequestPacket;
        RegisterRequestPacket_deserialize(&registerRequestPacket, buffer);

        handleRegisterRequest(sd, &registerRequestPacket);
        memset(&registerRequestPacket, 0, sizeof(registerRequestPacket));
    }
    else if (packetType == e_LoginRequest)
    {
        status = recvBufferTcp(sd, buffer + 1, LoginRequestPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return NULL;
        }

        LoginRequestPacket loginRequestPacket;
        LoginRequestPacket_deserialize(&loginRequestPacket, buffer);

        handleLoginRequest(sd, &loginRequestPacket);
        memset(&loginRequestPacket, 0, sizeof(loginRequestPacket));
    }
    else if (packetType == e_Logout)
    {
        status = recvBufferTcp(sd, buffer + 1, LogoutPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "recvBufferTcp() failed\n");
            close(sd);
            return NULL;
        }

        LogoutPacket logoutPacket;
        LogoutPacket_deserialize(&logoutPacket, buffer);

        handleLogout(&logoutPacket);
        memset(&logoutPacket, 0, sizeof(logoutPacket));
    }

    while (isCommandPacket && !isStopped)
    {
        if (verbose)
        {
            printf("Received command packet from %s\n", sourceAddressStr);
        }
        memset(&commandPacket, 0, sizeof(commandPacket));
        status = recvBufferTcp(sd, buffer + 1, CommandPacket_SIZE - 1);
        if (!status)
        {
            fprintf(stderr, "Failed to receive command\n");
            break;
        }

        CommandPacket_deserialize(&commandPacket, buffer);

        if (commandPacket.packetType != e_Command)
        {
            break;
        }

        if (!validateClient(commandPacket.connectionId, commandPacket.sessionKey))
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

        char commandStr[224] = {0};
        int commandStrLen = sizeof(commandStr);

        const uint8_t *iv = commandPacket.data + 224;
        uint8_t *tag = commandPacket.data + 240;
        if (!aesDecrypt(reinterpret_cast<uint8_t *>(commandStr), &commandStrLen, commandPacket.data, 224, aesKey, iv, tag))
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

        if (verbose)
        {
            printf("Recevied command: %s\n", commandStr + 32);
        }

        if (command == "READ_FILE")
        {
            handleReadFileCommand(sd, hostId, serviceId, aesKey);
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

            std::string tempFileFolder = TEMP_FILES_PATH + "/" + destinationHostId +
                                         "/" + destinationServiceId + "/";
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

            if (verbose)
            {
                printf("Writing to %s\n", tempFilePath.c_str());
            }

            fs::create_directories(tempFileFolder);
            char *filename =
                recvFile(sd, tempFilePrefix.c_str(), aesKey, e_ServerRecv);

            if (filename != NULL)
            {
                if (verbose)
                {
                    printf("File '%s' received successfully\n", filename);
                }
                int32_t tag = 0;
                fileQueue->pushFile(destinationHostId, destinationServiceId,
                                    tempFilePath, &tag);
                asyncThreadPool->notifyService(destinationHostId, destinationServiceId, e_FileEvent, tag);
                delete[] filename;
            }
            else
            {
                if (verbose)
                {
                    printf("Failed to received file\n");
                }
            }
        }
        else if (command == "LISTEN")
        {
            if (tokens.size() != 2)
            {
                break;
            }
            const std::string &eventType = tokens[1];

            if (eventType == "FILES")
            {
                asyncThreadPool->addService(hostId, serviceId, e_FileEvent, sd, aesKey);
                return NULL;
            }
        }

        break;
    }

    if (aesKey != NULL)
    {
        memset(aesKey, 0, 32);
        delete[] aesKey;
        aesKey = NULL;
    }

    close(sd);

    return NULL;
}

void *dataThread(void *)
{
    if (listen(serverSocket, 5) < 0)
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

        fds[0].fd = serverSocket;
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

        int sd =
            accept(serverSocket, reinterpret_cast<struct sockaddr *>(&sourceAddress),
                   &sourceAddressLen);
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
        pthread_detach(threadId);
    }

    return NULL;
}

bool start()
{
    loginSystem = LoginSystem::getInstance();
    fileQueue = FileQueue::getInstance();
    asyncThreadPool = AsyncThreadPool::getInstance();
    if (!loginSystem->start())
    {
        fprintf(stderr, "Failed to start login system\n");
        return false;
    }

    if (!asyncThreadPool->start())
    {
        fprintf(stderr, "Failed to start async thread pool\n");
        loginSystem->stop();
        return false;
    }

    if (!initializeSecurity())
    {
        return false;
    }

    serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        cleanSecurity();
        loginSystem->stop();
        asyncThreadPool->stop();
        return false;
    }

    struct linger ling;
    ling.l_onoff = 0;
    ling.l_linger = 0;

    int optval = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    serverAddress.sin6_family = AF_INET6;
    serverAddress.sin6_addr = in6addr_any;
    serverAddress.sin6_port = htons(serverPort);
    serverAddress.sin6_flowinfo = 0;
    serverAddress.sin6_scope_id = 0;

    if (bind(serverSocket, reinterpret_cast<const struct sockaddr *>(&serverAddress),
             sizeof(serverAddress)) < 0)
    {
        fprintf(stderr, "bind()  failed [%d]\n", errno);
        cleanSecurity();
        loginSystem->stop();
        asyncThreadPool->stop();
        return false;
    }

    signal(SIGINT, terminationHandler);
    signal(SIGTSTP, terminationHandler);

    signal(SIGPIPE, SIG_IGN);

    pthread_create(&dataThreadId, NULL, dataThread, NULL);

    return true;
}

void stop()
{
    close(serverSocket);

    loginSystem->stop();

    cleanSecurity();

    sleep(1);
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

    std::cout << "HomeLink server listening on port " << serverPort << std::endl;
    pthread_join(dataThreadId, NULL);

    stop();

    std::cout << "Homelink server stopped" << std::endl;

    return 0;
}
