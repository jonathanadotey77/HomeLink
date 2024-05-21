#include <homelink_packet.h>

#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <string.h>

const char *getPacketStr(HomeLinkPacketType packetType)
{
    switch (packetType)
    {
    case e_Ping:
        return PingPacket_STR;
    case e_ConnectionRequest:
        return ConnectionRequestPacket_STR;
    case e_ConnectionResponse:
        return ConnectionResponsePacket_STR;
    case e_Command:
        return CommandPacket_STR;
    case e_LoginRequest:
        return LoginRequestPacket_STR;
    case e_LoginResponse:
        return LoginResponsePacket_STR;
    case e_RegisterRequest:
        return RegisterRequestPacket_STR;
    case e_RegisterResponse:
        return RegisterResponsePacket_STR;
    case e_Logout:
        return LogoutPacket_STR;
    case e_AsyncListenRequest:
        return AsyncListenRequestPacket_STR;
    case e_AsyncNotification:
        return AsyncNotificationPacket_STR;
    default:
        return "<Error-Packet-Type>";
    }
}

const char *PingPacket_STR = "Ping";
const int32_t PingPacket_SIZE = sizeof(((PingPacket){0}).packetType) + sizeof(((PingPacket){0}).value);

void PingPacket_serialize(uint8_t *buffer, const PingPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *value = (uint32_t *)(buffer + sizeof(packet->packetType));

    *packetType = packet->packetType;
    *value = htonl(packet->value);
}

void PingPacket_deserialize(PingPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *value = (const uint32_t *)(buffer + sizeof(packet->packetType));

    packet->packetType = *packetType;
    packet->value = ntohl(*value);
}

const char *ConnectionRequestPacket_STR = "ConnectionRequest";
const int32_t ConnectionRequestPacket_SIZE = sizeof(((ConnectionRequestPacket){0}).packetType) + sizeof(((ConnectionRequestPacket){0}).connectionId) + sizeof(((ConnectionRequestPacket){0}).rsaPublicKey);

void ConnectionRequestPacket_serialize(uint8_t *buffer, const ConnectionRequestPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));

    rsaPublicKey[sizeof(packet->rsaPublicKey) - 1] = '\0';
}

void ConnectionRequestPacket_deserialize(ConnectionRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));

    packet->rsaPublicKey[sizeof(packet->rsaPublicKey) - 1] = '\0';
}

const char *ConnectionResponsePacket_STR = "ConnectionResponse";
const int32_t ConnectionResponsePacket_SIZE = sizeof(((ConnectionResponsePacket){0}).packetType) + sizeof(((ConnectionResponsePacket){0}).success) + sizeof(((ConnectionResponsePacket){0}).rsaPublicKey) + sizeof(((ConnectionResponsePacket){0}).aesKey);

void ConnectionResponsePacket_serialize(uint8_t *buffer, const ConnectionResponsePacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *success = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    uint8_t *aesKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    *packetType = packet->packetType;
    *success = packet->success;
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(aesKey, &packet->aesKey, sizeof(packet->aesKey));

    rsaPublicKey[sizeof(packet->rsaPublicKey) - 1] = '\0';
}

void ConnectionResponsePacket_deserialize(ConnectionResponsePacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *success = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    const uint8_t *aesKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    packet->success = *success;
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(packet->aesKey, aesKey, sizeof(packet->aesKey));

    packet->rsaPublicKey[sizeof(packet->rsaPublicKey) - 1] = '\0';
}

const char *CommandPacket_STR = "Command";
const int32_t CommandPacket_SIZE = sizeof(((CommandPacket){0}).packetType) + sizeof(((CommandPacket){0}).connectionId) + sizeof(((CommandPacket){0}).sessionKey) + sizeof(((CommandPacket){0}).data);

void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType));
    uint8_t *sessionKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->sessionKey));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(sessionKey, packet->sessionKey, sizeof(packet->sessionKey));
    memcpy(data, packet->data, sizeof(packet->data));
}
void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType));
    const uint8_t *sessionKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->sessionKey));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->sessionKey, sessionKey, sizeof(packet->sessionKey));
    memcpy(packet->data, data, sizeof(packet->data));
}

const char *LoginRequestPacket_STR = "LoginRequest";
const int32_t LoginRequestPacket_SIZE = sizeof(((LoginRequestPacket){0}).packetType) + sizeof(((LoginRequestPacket){0}).connectionId) + sizeof(((LoginRequestPacket){0}).hostId) + sizeof(((LoginRequestPacket){0}).serviceId) + sizeof(((LoginRequestPacket){0}).data);

void LoginRequestPacket_serialize(uint8_t *buffer, const LoginRequestPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType));
    char *hostId = (char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    char *serviceId = (char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->hostId));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->hostId) + sizeof(packet->serviceId));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(hostId, packet->hostId, sizeof(packet->hostId));
    memcpy(serviceId, packet->serviceId, sizeof(packet->serviceId));
    memcpy(data, packet->data, sizeof(packet->data));

    hostId[sizeof(packet->hostId) - 1] = '\0';
    serviceId[sizeof(packet->hostId) - 1] = '\0';
}

void LoginRequestPacket_deserialize(LoginRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType));
    const char *hostId = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    const char *serviceId = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->hostId));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->hostId) + sizeof(packet->serviceId));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->hostId, hostId, sizeof(packet->hostId));
    memcpy(packet->serviceId, serviceId, sizeof(packet->serviceId));
    memcpy(packet->data, data, sizeof(packet->data));

    packet->hostId[sizeof(packet->hostId) - 1] = '\0';
    packet->serviceId[sizeof(packet->hostId) - 1] = '\0';
}

const char *LoginResponsePacket_STR = "LoginResponse";
const int32_t LoginResponsePacket_SIZE = sizeof(((LoginResponsePacket){0}).packetType) + sizeof(((LoginResponsePacket){0}).packetType) + sizeof(((LoginResponsePacket){0}).sessionKey);

void LoginResponsePacket_serialize(uint8_t *buffer, const LoginResponsePacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *status = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint8_t *sessionKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->status));

    *packetType = packet->packetType;
    *status = packet->status;
    memcpy(sessionKey, packet->sessionKey, sizeof(packet->sessionKey));
}

void LoginResponsePacket_deserialize(LoginResponsePacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *status = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const uint8_t *sessionKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->status));

    packet->packetType = *packetType;
    packet->status = *status;
    memcpy(packet->sessionKey, sessionKey, sizeof(packet->sessionKey));
}

const char *RegisterRequestPacket_STR = "RegisterRequest";
const int32_t RegisterRequestPacket_SIZE = sizeof(((RegisterRequestPacket){0}).packetType) + sizeof(((RegisterRequestPacket){0}).registrationType) + sizeof(((RegisterRequestPacket){0}).hostId) + sizeof(((RegisterRequestPacket){0}).serviceId) + sizeof(((RegisterRequestPacket){0}).data);

void RegisterRequestPacket_serialize(uint8_t *buffer, const RegisterRequestPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *registrationType = (uint8_t *)(buffer + sizeof(packet->packetType));
    char *hostId = (char *)(buffer + sizeof(packet->packetType) + sizeof(packet->registrationType));
    char *serviceId = (char *)(buffer + sizeof(packet->packetType) + sizeof(packet->registrationType) + sizeof(packet->hostId));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->registrationType) + sizeof(packet->hostId) + sizeof(packet->serviceId));

    *packetType = packet->packetType;
    *registrationType = packet->registrationType;
    memcpy(hostId, packet->hostId, sizeof(packet->hostId));
    memcpy(serviceId, packet->serviceId, sizeof(packet->serviceId));
    memcpy(data, packet->data, sizeof(packet->data));

    hostId[sizeof(packet->hostId) - 1] = '\0';
    serviceId[sizeof(packet->serviceId) - 1] = '\0';
}

const char *RegisterResponsePacket_STR = "RegisterResponse";
void RegisterRequestPacket_deserialize(RegisterRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *registrationType = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const char *hostId = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->registrationType));
    const char *serviceId = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->registrationType) + sizeof(packet->hostId));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->registrationType) + sizeof(packet->hostId) + sizeof(packet->serviceId));

    packet->packetType = *packetType;
    packet->registrationType = *registrationType;
    memcpy(packet->hostId, hostId, sizeof(packet->hostId));
    memcpy(packet->serviceId, serviceId, sizeof(packet->serviceId));
    memcpy(packet->data, data, sizeof(packet->data));

    packet->hostId[sizeof(packet->hostId) - 1] = '\0';
    packet->serviceId[sizeof(packet->hostId) - 1] = '\0';
}

const int32_t RegisterResponsePacket_SIZE = sizeof(((RegisterResponsePacket){0}).packetType) + sizeof(((RegisterResponsePacket){0}).status);

void RegisterResponsePacket_serialize(uint8_t *buffer, const RegisterResponsePacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *status = (uint8_t *)(buffer + sizeof(packet->packetType));

    *packetType = packet->packetType;
    *status = packet->status;
}

void RegisterResponsePacket_deserialize(RegisterResponsePacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *status = (const uint8_t *)(buffer + sizeof(packet->packetType));

    packet->packetType = *packetType;
    packet->status = *status;
}

const char *LogoutPacket_STR = "Logout";
const int32_t LogoutPacket_SIZE = sizeof(((LogoutPacket){0}).packetType) + sizeof(((LogoutPacket){0}).connectionId) + sizeof(((LogoutPacket){0}).sessionKey);

void LogoutPacket_serialize(uint8_t *buffer, const LogoutPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType));
    uint8_t *sessionKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(sessionKey, packet->sessionKey, sizeof(packet->sessionKey));
}

void LogoutPacket_deserialize(LogoutPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType));
    const uint8_t *sessionKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->sessionKey, sessionKey, sizeof(packet->sessionKey));
}

const char *AsyncListenRequestPacket_STR = "AsyncListen";
const int32_t AsyncListenRequestPacket_SIZE = sizeof(((AsyncListenRequestPacket){0}).packetType) + sizeof(((AsyncListenRequestPacket){0}).eventType) + sizeof(((AsyncListenRequestPacket){0}).connectionId) + sizeof(((AsyncListenRequestPacket){0}).sessionKey);

void AsyncListenRequestPacket_serialize(uint8_t *buffer, const AsyncListenRequestPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *eventType = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->eventType));
    uint8_t *sessionKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->eventType) + sizeof(packet->connectionId));

    *packetType = packet->packetType;
    *eventType = packet->eventType;
    *connectionId = htonl(packet->connectionId);
    memcpy(sessionKey, packet->sessionKey, sizeof(packet->sessionKey));
}

void AsyncListenRequestPacket_deserialize(AsyncListenRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *eventType = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->eventType));
    const uint8_t *sessionKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->eventType) + sizeof(packet->connectionId));

    packet->packetType = *packetType;
    packet->eventType = *eventType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->sessionKey, sessionKey, sizeof(packet->sessionKey));
}

const char *AsyncNotificationPacket_STR = "AsyncNotification";
const int32_t AsyncNotificationPacket_SIZE = sizeof(((AsyncNotificationPacket){0}).packetType) + sizeof(((AsyncNotificationPacket){0}).eventType) + sizeof(((AsyncNotificationPacket){0}).tag);

void AsyncNotificationPacket_serialize(uint8_t *buffer, const AsyncNotificationPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *eventType = (uint8_t *)(buffer + sizeof(packet->packetType));
    int32_t *tag = (int32_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->eventType));

    *packetType = packet->packetType;
    *eventType = packet->eventType;
    *tag = htonl(packet->tag);
}

void AsyncNotificationPacket_deserialize(AsyncNotificationPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *eventType = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const int32_t *tag = (const int32_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->eventType));

    packet->packetType = *packetType;
    packet->eventType = *eventType;
    packet->tag = ntohl(*tag);
}
