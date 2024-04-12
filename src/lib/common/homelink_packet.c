#include <homelink_packet.h>

#include <arpa/inet.h>
#include <string.h>

const uint32_t CLIPacket_SIZE = sizeof(((CLIPacket){0}).packetType) + sizeof(((CLIPacket){0}).rsaPublicKey) + sizeof(((CLIPacket){0}).data);

void CLIPacket_serialize(uint8_t *buffer, const CLIPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->rsaPublicKey));

    *packetType = packet->packetType;
    memcpy(rsaPublicKey, packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(data, packet->data, sizeof(packet->data));
}
void CLIPacket_deserialize(CLIPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *rsaPublicKey = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(packet->data, data, sizeof(packet->data));
}

const uint32_t AckPacket_SIZE = sizeof(((AckPacket){0}).packetType) + sizeof(((AckPacket){0}).value);

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

const uint32_t KeyRequestPacket_SIZE = sizeof(((KeyRequestPacket){0}).packetType) + sizeof(((KeyRequestPacket){0}).connectionId) + sizeof(((KeyRequestPacket){0}).rsaPublicKey);

void KeyRequestPacket_serialize(uint8_t *buffer, const KeyRequestPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t *)(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    *packetType = packet->packetType;
    *connectionId = htonl(packet->connectionId);
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
}

void KeyRequestPacket_deserialize(KeyRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t *)(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(&packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
}

const uint32_t KeyResponsePacket_SIZE = sizeof(((KeyResponsePacket){0}).packetType) + sizeof(((KeyResponsePacket){0}).success) + sizeof(((KeyResponsePacket){0}).rsaPublicKey) + sizeof(((KeyResponsePacket){0}).aesKey);

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
}

void KeyResponsePacket_deserialize(KeyResponsePacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *success = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = (const char *)(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    const uint8_t *aesKey = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    packet->success = *success;
    memcpy(&packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(&packet->aesKey, aesKey, sizeof(packet->aesKey));
}

const uint32_t CommandPacket_SIZE = sizeof(((CommandPacket){0}).packetType) + sizeof(((CommandPacket){0}).command) + sizeof(((CommandPacket){0}).data);

void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet)
{
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *command = (uint8_t *)(buffer + sizeof(packet->packetType));
    uint8_t *data = (uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->command));

    *packetType = packet->packetType;
    memcpy(command, packet->command, sizeof(packet->command));
    memcpy(data, packet->data, sizeof(packet->data));
}
void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *command = (const uint8_t *)(buffer + sizeof(packet->packetType));
    const uint8_t *data = (const uint8_t *)(buffer + sizeof(packet->packetType) + sizeof(packet->command));

    packet->packetType = *packetType;
    memcpy(packet->command, command, sizeof(packet->command));
    memcpy(packet->data, data, sizeof(packet->data));
}

const uint32_t LoginRequestPacket_SIZE = sizeof(((LoginRequestPacket){0}).packetType) + sizeof(((LoginRequestPacket){0}).salt) + sizeof(((LoginRequestPacket){0}).username) + sizeof(((LoginRequestPacket){0}).password);

void LoginRequestPacket_serialize(uint8_t *buffer, const LoginRequestPacket *packet) {
    uint8_t *packetType = (uint8_t *)(buffer);
    uint32_t *connectionId = (uint32_t*)(buffer + sizeof(packet->packetType));
    uint8_t *salt = (uint8_t*)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    char* username = (char*)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->salt));
    uint8_t* password = (uint8_t*)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->salt) + sizeof(packet->username));

    *packetType = packet->packetType;
    *connectionId = htonl(*connectionId);
    memcpy(salt, packet->salt, sizeof(packet->salt));
    memcpy(username, packet->username, sizeof(packet->username));
    memcpy(password, packet->password, sizeof(packet->password));
}

void LoginRequestPacket_deserialize(LoginRequestPacket *packet, const uint8_t *buffer) {
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint32_t *connectionId = (const uint32_t*)(buffer + sizeof(packet->packetType));
    const uint8_t *salt = (const uint8_t*)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId));
    const char* username = (const char*)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->salt));
    const uint8_t* password = (const uint8_t*)(buffer + sizeof(packet->packetType) + sizeof(packet->connectionId) + sizeof(packet->salt) + sizeof(packet->username));

    packet->packetType = *packetType;
    packet->connectionId = ntohl(*connectionId);
    memcpy(packet->salt, salt, sizeof(packet->salt));
    memcpy(packet->username, username, sizeof(packet->username));
    memcpy(packet->password, password, sizeof(packet->password));
}

const uint32_t LoginResponsePacket_SIZE = sizeof(((LoginResponsePacket){0}).packetType) + sizeof(((LoginResponsePacket){0}).sessionToken);

void LoginResponsePacket_serialize(uint8_t *buffer, const LoginResponsePacket *packet) {
    uint8_t *packetType = (uint8_t *)(buffer);
    uint8_t *sessionToken = (uint8_t*)(buffer + sizeof(packet->packetType));

    *packetType = packet->packetType;
    memcpy(sessionToken, packet->sessionToken, sizeof(packet->sessionToken));
}

void LoginResponsePacket_deserialize(LoginResponsePacket *packet, const uint8_t *buffer) {
    const uint8_t *packetType = (const uint8_t *)(buffer);
    const uint8_t *sessionToken = (const uint8_t*)(buffer + sizeof(packet->packetType));

    packet->packetType = *packetType;
    memcpy(packet->sessionToken, sessionToken, sizeof(packet->sessionToken));
}