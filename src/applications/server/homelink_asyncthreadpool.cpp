#include <homelink_asyncthreadpool.h>

#include <homelink_misc.h>
#include <homelink_net.h>
#include <homelink_packet.h>
#include <homelink_server.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>

static volatile bool stopped = true;
std::unordered_set<pthread_t> activeThreadIds;
std::mutex activeThreadIdsLock;

static in_addr_t LOCALHOST = inet_addr("127.0.0.1");

typedef struct AsyncClientThreadArgs
{
    int localSocket;
    int clientSocket;
    std::string hostId;
    std::string serviceId;
    AsyncThreadPool *asyncThreadPool;
    AsyncEventType eventType;
    const uint8_t *aesKey;
} AsyncClientThreadArgs;

static bool isActiveThread(pthread_t threadId)
{
    bool active = false;
    activeThreadIdsLock.lock();

    active = activeThreadIds.find(threadId) != activeThreadIds.end();

    activeThreadIdsLock.unlock();

    if (active)
    {
        printf("found %llu\n", (unsigned long long)threadId);
    }

    return active;
}

void *AsyncThreadPool::clientThread(void *a)
{
    activeThreadIdsLock.lock();
    const pthread_t threadId = pthread_self();
    activeThreadIds.insert(threadId);
    activeThreadIdsLock.unlock();
    AsyncClientThreadArgs *args = reinterpret_cast<AsyncClientThreadArgs *>(a);

    const int localSocket = args->localSocket;
    const int clientSocket = args->clientSocket;
    const std::string hostId = args->hostId;
    const std::string serviceId = args->serviceId;
    AsyncThreadPool *asyncThreadPool = args->asyncThreadPool;
    const AsyncEventType eventType = args->eventType;
    const uint8_t *aesKey = args->aesKey;

    delete args;

    struct pollfd fds[1];
    uint8_t buffer[AsyncNotificationPacket_SIZE];

    struct sockaddr_in sourceAddress;
    socklen_t sourceAddressLen = sizeof(sourceAddress);

    while (!stopped && isActiveThread(threadId))
    {
        memset(buffer, 0, sizeof(buffer));
        fds[0].fd = localSocket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        int rc = poll(fds, 1, 3000);
        if (rc < 0)
        {
            fprintf(stderr, "poll() failed [%d]\n", errno);
        }
        else if (rc == 0)
        {
            continue;
        }

        rc = recvfrom(localSocket, buffer, sizeof(buffer), 5, reinterpret_cast<struct sockaddr *>(&sourceAddress), &sourceAddressLen);
        if (rc < 0)
        {
            fprintf(stderr, "recvfrom() failed [%d]\n", errno);
            break;
        }

        const AsyncEventType val = static_cast<AsyncEventType>(buffer[0]);
        const int32_t tag = ntohl(*(reinterpret_cast<int32_t *>(buffer + 1)));
        memset(buffer, 0, 5);

        if (val == e_FileEvent)
        {
            // Send noficiation to client
            if (verbose)
            {
                printf("Sending file event notification to {%s | %s}\n", hostId.c_str(), serviceId.c_str());
            }

            AsyncNotificationPacket asyncNotificationPacket;
            asyncNotificationPacket.packetType = e_AsyncNotification;
            asyncNotificationPacket.eventType = static_cast<uint8_t>(e_FileEvent);
            asyncNotificationPacket.tag = tag;
            AsyncNotificationPacket_serialize(buffer, &asyncNotificationPacket);
            bool status = sendBufferTcp(clientSocket, buffer, sizeof(buffer));
            if (!status)
            {
                fprintf(stderr, "sendBufferTcp() failed\n");
                break;
            }

            if (verbose)
            {
                printf("Sent file event notification to {%s | %s}\n", hostId.c_str(), serviceId.c_str());
            }
        }
    }

    close(localSocket);
    close(clientSocket);
    delete[] aesKey;
    if (isActiveThread(threadId))
    {
        asyncThreadPool->removeService(hostId, serviceId, eventType);
    }

    return NULL;
}

static std::mutex asyncThreadPoolLock;

AsyncThreadPool *AsyncThreadPool::getInstance()
{
    static AsyncThreadPool instance;
    return &instance;
}

bool AsyncThreadPool::start()
{
    this->notoficationSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (this->notoficationSocket < 0)
    {
        fprintf(stderr, "socket() failed [%d]\n", errno);
        return false;
    }

    this->notificationPort = randomPort(20000, 29999);

    this->notificationAddress.sin_family = AF_INET;
    this->notificationAddress.sin_addr.s_addr = LOCALHOST;
    this->notificationAddress.sin_port = htons(notificationPort);

    if (bind(this->notoficationSocket, reinterpret_cast<const struct sockaddr *>(&notificationAddress), static_cast<socklen_t>(sizeof(notificationAddress))) < 0)
    {
        fprintf(stderr, "bind() failed [%d]\n", errno);
        return false;
    }

    stopped = false;

    return true;
}

void AsyncThreadPool::stop()
{
    asyncThreadPoolLock.lock();
    stopped = true;
    asyncThreadPoolLock.unlock();
}

bool AsyncThreadPool::findService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType)
{
    return this->clientInfoMap.find(hostId) != this->clientInfoMap.end() && this->clientInfoMap[hostId].find(serviceId) != this->clientInfoMap[hostId].end() && (eventType == e_AnyEvent || this->clientInfoMap[hostId][serviceId].find(eventType) != this->clientInfoMap[hostId][serviceId].end());
}

bool AsyncThreadPool::addService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType, int clientSocket, const uint8_t *aesKey)
{
    bool status = false;
    asyncThreadPoolLock.lock();
    if (!this->findService(hostId, serviceId, eventType))
    {
        uint16_t port = randomPort(30000, 59999);
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = LOCALHOST;
        address.sin_port = htons(port);
        int sd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sd < 0)
        {
            fprintf(stderr, "socket() failed [%d]\n", errno);
        }
        else if (bind(sd, reinterpret_cast<const struct sockaddr *>(&address), static_cast<socklen_t>(sizeof(address))) < 0)
        {
            fprintf(stderr, "bind() failed [%d]\n", errno);
        }
        else if (connect(sd, reinterpret_cast<const struct sockaddr *>(&this->notificationAddress), static_cast<socklen_t>(sizeof(this->notificationAddress))) < 0)
        {
            fprintf(stderr, "connect() failed [%d]\n", errno);
        }
        else
        {
            status = true;

            pthread_t threadId;
            AsyncClientThreadArgs *args = new AsyncClientThreadArgs;
            args->localSocket = sd;
            args->clientSocket = clientSocket;
            args->hostId = hostId;
            args->serviceId = serviceId;
            args->asyncThreadPool = this;
            args->eventType = eventType;
            args->aesKey = aesKey;

            pthread_create(&threadId, NULL, clientThread, args);
            pthread_detach(threadId);
            ClientInfo clientInfo;
            clientInfo.port = port;
            clientInfo.threadId = threadId;
            this->clientInfoMap[hostId][serviceId][eventType] = clientInfo;
            if (verbose)
            {
                printf("Added service {%s | %s} to async thread pool\n", hostId.c_str(), serviceId.c_str());
            }
        }
    }
    asyncThreadPoolLock.unlock();

    return status;
}

void AsyncThreadPool::removeService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType)
{
    asyncThreadPoolLock.lock();
    if (this->findService(hostId, serviceId, eventType))
    {
        activeThreadIdsLock.lock();
        if (eventType == e_AnyEvent)
        {
            for (auto itr = this->clientInfoMap[hostId][serviceId].begin(); itr != this->clientInfoMap[hostId][serviceId].end(); ++itr)
            {
                activeThreadIds.erase(itr->second.threadId);
                printf("Erasing %llu\n", (unsigned long long)itr->second.threadId);
            }
        }
        else
        {
            printf("Erasing %llu\n", (unsigned long long)this->clientInfoMap[hostId][serviceId][eventType].threadId);
            activeThreadIds.erase(this->clientInfoMap[hostId][serviceId][eventType].threadId);
        }
        activeThreadIdsLock.unlock();
        this->clientInfoMap[hostId][serviceId].erase(eventType);

        if (eventType == e_AnyEvent || this->clientInfoMap[hostId][serviceId].empty())
        {

            this->clientInfoMap[hostId].erase(serviceId);
            if (this->clientInfoMap[hostId].empty())
            {
                this->clientInfoMap.erase(hostId);
            }
        }

        asyncThreadPoolLock.unlock();
        if (verbose)
        {
            printf("Removed service {%s | %s} from async thread pool\n", hostId.c_str(), serviceId.c_str());
        }
    }
    else
    {
        asyncThreadPoolLock.unlock();
    }
}

bool AsyncThreadPool::notifyService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType, int32_t tag)
{
    asyncThreadPoolLock.lock();
    if (this->findService(hostId, serviceId, eventType))
    {
        if (verbose)
        {
            printf("Notifying service {%s | %s}\n", hostId.c_str(), serviceId.c_str());
        }

        uint8_t buffer[5] = {0};
        buffer[0] = eventType;
        *(reinterpret_cast<int32_t *>(buffer + 1)) = htonl(tag);
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = LOCALHOST;
        address.sin_port = htons(this->clientInfoMap[hostId][serviceId][eventType].port);

        int rc = sendto(this->notoficationSocket, buffer, sizeof(buffer), 0, reinterpret_cast<const struct sockaddr *>(&address), static_cast<socklen_t>(sizeof(address)));
        if (rc < 0)
        {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
        }
    }
    asyncThreadPoolLock.unlock();

    return true;
}
