#ifndef HOMELINK_ASYNCTHREADPOOL_H
#define HOMELINK_ASYNCTHREADPOOL_H

#include <homelink_aeskey.h>
#include <homelink_packet.h>
#include <homelink_server.h>

#include <arpa/inet.h>
#include <cstdint>
#include <pthread.h>
#include <string>
#include <unordered_map>

// SINGLETON
class AsyncThreadPool
{
private:
    typedef struct ClientInfo
    {
        uint16_t port;
        pthread_t threadId;
    } ClientInfo;

private:
    int notoficationSocket;
    struct sockaddr_in notificationAddress;
    uint16_t notificationPort;
    std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<AsyncEventType, ClientInfo>>> clientInfoMap;

private:
    static void *clientThread(void *a);
    AsyncThreadPool() : notoficationSocket(-1), notificationPort(0) {}

    // Not thread safe, only to be called within critical sections.
    bool findService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType);

public:
    static AsyncThreadPool *getInstance();

    bool start();

    void stop();

    bool addService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType, int clientSocket);

    void removeService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType);

    bool notifyService(const std::string &hostId, const std::string &serviceId, AsyncEventType eventType, int32_t tag);
};

#endif
