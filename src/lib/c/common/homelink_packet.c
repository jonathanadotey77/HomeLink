#include <homelink_packet.h>

#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <string.h>

#if __BIG_ENDIAN
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

const int32_t CLIPacket_SIZE = sizeof(((CLIPacket){0}).packetType) + sizeof(((CLIPacket){0}).rsaPublicKey) + sizeof(((CLIPacket){0}).data);

void CLIPacket_serialize(uint8_t *buffer, const CLIPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->rsaPublicKey));

    *packetType = packet->packetType;
    memcpy(rsaPublicKey, packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(data, packet->data, sizeof(packet->data));

    rsaPublicKey[sizeof(packet->rsaPublicKey)-1] = '\0';
}
void CLIPacket_deserialize(CLIPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *rsaPublicKey = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(packet->data, data, sizeof(packet->data));

    packet->rsaPublicKey[sizeof(packet->rsaPublicKey)-1] = '\0';
}

const int32_t AckPacket_SIZE = sizeof(((AckPacket){0}).packetType) + sizeof(((AckPacket){0}).value);

void AckPacket_serialize(uint8_t *buffer, const AckPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *value = (uint32_t *)(buffer + sizeof(packet->packetType));

    *packetType = packet->packetType;
    *value = htonl(packet->value);
}

void AckPacket_deserialize(AckPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *value = (const uint32_t *)(buffer + sizeof(packet->packetType));

    packet->packetType = *packetType;
    packet->value = ntohl(*value);
}

const int32_t KeyRequestPacket_SIZE = sizeof(((KeyRequestPacket){0}).packetType) + sizeof(((KeyRequestPacket){0}).connectionId) + sizeof(((KeyRequestPacket){0}).rsaPublicKey);

void KeyRequestPacket_serialize(uint8_t *buffer, const KeyRequestPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));

    rsaPublicKey[sizeof(packet->rsaPublicKey)-1] = '\0';
}

void KeyRequestPacket_deserialize(KeyRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));

    packet->rsaPublicKey[sizeof(packet->rsaPublicKey)-1] = '\0';
}

const int32_t KeyResponsePacket_SIZE = sizeof(((KeyResponsePacket){0}).packetType) + sizeof(((KeyResponsePacket){0}).success) + sizeof(((KeyResponsePacket){0}).rsaPublicKey) + sizeof(((KeyResponsePacket){0}).aesKey);

void KeyResponsePacket_serialize(uint8_t *buffer, const KeyResponsePacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *success = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    uint8_t *aesKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    *packetType = packet->packetType;
    *success = packet->success;
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(aesKey, &packet->aesKey, sizeof(packet->aesKey));

    rsaPublicKey[sizeof(packet->rsaPublicKey)-1] = '\0';
}

void KeyResponsePacket_deserialize(KeyResponsePacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *success = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    const uint8_t *aesKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    packet->success = *success;
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(packet->aesKey, aesKey, sizeof(packet->aesKey));

    packet->rsaPublicKey[sizeof(packet->rsaPublicKey)-1] = '\0';
}

const int32_t CommandPacket_SIZE = sizeof(((CommandPacket){0}).packetType) + sizeof(((CommandPacket){0}).connectionId) + sizeof(((CommandPacket){0}).sessionToken) + sizeof(((CommandPacket){0}).data);

void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t*)(buffer + sizeof(packet->packetType));
    uint8_t *sessionToken = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType)+ sizeof(packet->connectionId) + sizeof(packet->sessionToken));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(sessionToken, packet->sessionToken, sizeof(packet->sessionToken));
    memcpy(data, packet->data, sizeof(packet->data));
}
void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t*)(buffer + sizeof(packet->packetType));
    const uint8_t *sessionToken = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType)+ sizeof(packet->connectionId) + sizeof(packet->sessionToken));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->sessionToken, sessionToken, sizeof(packet->sessionToken));
    memcpy(packet->data, data, sizeof(packet->data));
}

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

    hostId[sizeof(packet->hostId)-1] = '\0';
    serviceId[sizeof(packet->hostId)-1] = '\0';
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

    packet->hostId[sizeof(packet->hostId)-1] = '\0';
    packet->serviceId[sizeof(packet->hostId)-1] = '\0';
}

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

const int32_t RegisterRequestPacket_SIZE = sizeof(((RegisterRequestPacket){0}).packetType) + sizeof(((RegisterRequestPacket){0}).connectionId) + sizeof(((RegisterRequestPacket){0}).hostId) + sizeof(((RegisterRequestPacket){0}).serviceId) + sizeof(((RegisterRequestPacket){0}).data);

void RegisterRequestPacket_serialize(uint8_t *buffer, const RegisterRequestPacket *packet)
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

    hostId[sizeof(packet->hostId)-1] = '\0';
    serviceId[sizeof(packet->hostId)-1] = '\0';
}

void RegisterRequestPacket_deserialize(RegisterRequestPacket *packet, const uint8_t *buffer)
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
    packet->hostId[sizeof(packet->hostId)-1] = '\0';
    packet->serviceId[sizeof(packet->hostId)-1] = '\0';
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

const int32_t LogoutPacket__SIZE = sizeof(((LogoutPacket){0}).packetType) + sizeof(((LogoutPacket){0}).connectionId) + sizeof(((LogoutPacket){0}).sessionKey);

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
