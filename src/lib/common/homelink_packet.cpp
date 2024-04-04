#include <homelink_packet.h>

#include <arpa/inet.h>
#include <string.h>

void CommandPacket_serialize(uint8_t* buffer, const CommandPacket* packet) {
    uint8_t *packetType = reinterpret_cast<uint8_t *>(buffer);
    uint8_t *rsaPublicKey = reinterpret_cast<uint8_t *>(buffer + sizeof(packet->packetType));
    uint8_t *data = reinterpret_cast<uint8_t*>(buffer + sizeof(packet->packetType) + sizeof(packet->rsaPublicKey));

    *packetType = packet->packetType;
    memcpy(rsaPublicKey, packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(data, packet->data, sizeof(packet->data));
}
void CommandPacket_deserialize(CommandPacket* packet, const uint8_t* buffer) {
    const uint8_t *packetType = reinterpret_cast<const uint8_t *>(buffer);
    const uint8_t *rsaPublicKey = reinterpret_cast<const uint8_t *>(buffer + sizeof(packet->packetType));
    const uint8_t *data = reinterpret_cast<const uint8_t*>(buffer + sizeof(packet->packetType) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    memcpy(packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(packet->data, data, sizeof(packet->data));
}

void AckPacket_serialize(uint8_t *buffer, const AckPacket *packet)
{
    uint8_t *packetType = reinterpret_cast<uint8_t *>(buffer);
    uint32_t *value = reinterpret_cast<uint32_t *>(buffer + sizeof(packet->packetType));

    *packetType = packet->packetType;
    *value = htonl(packet->value);
}

void AckPacket_deserialize(AckPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = reinterpret_cast<const uint8_t *>(buffer);
    const uint32_t *value = reinterpret_cast<const uint32_t *>(buffer + sizeof(packet->packetType));

    packet->packetType = *packetType;
    packet->value = ntohl(*value);
}

void KeyRequestPacket_serialize(uint8_t *buffer, const KeyRequestPacket *packet)
{
    uint8_t *packetType = reinterpret_cast<uint8_t *>(buffer);
    uint32_t *keysetId = reinterpret_cast<uint32_t *>(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = reinterpret_cast<uint8_t *>(buffer + sizeof(packet->packetType) + sizeof(packet->keysetId));

    *packetType = packet->packetType;
    *keysetId = htonl(packet->keysetId);
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
}

void KeyRequestPacket_deserialize(KeyRequestPacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = reinterpret_cast<const uint8_t *>(buffer);
    const uint32_t *keysetId = reinterpret_cast<const uint32_t *>(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = reinterpret_cast<const char *>(buffer + sizeof(packet->packetType) + sizeof(packet->keysetId));

    packet->packetType = *packetType;
    packet->keysetId = ntohl(*keysetId);
    memcpy(&packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
}

void KeyResponsePacket_serialize(uint8_t *buffer, const KeyResponsePacket *packet)
{
    uint8_t *packetType = reinterpret_cast<uint8_t *>(buffer);
    uint8_t *success = reinterpret_cast<uint8_t *>(buffer + sizeof(packet->packetType));
    uint8_t *rsaPublicKey = reinterpret_cast<uint8_t *>(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    uint8_t *aesKey = reinterpret_cast<uint8_t *>(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    *packetType = packet->packetType;
    *success = packet->success;
    memcpy(rsaPublicKey, &packet->rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(aesKey, &packet->aesKey, sizeof(packet->aesKey));
}

void KeyResponsePacket_deserialize(KeyResponsePacket *packet, const uint8_t *buffer)
{
    const uint8_t *packetType = reinterpret_cast<const uint8_t *>(buffer);
    const uint8_t *success = reinterpret_cast<const uint8_t *>(buffer + sizeof(packet->packetType));
    const char *rsaPublicKey = reinterpret_cast<const char *>(buffer + sizeof(packet->packetType) + sizeof(packet->success));
    const uint8_t *aesKey = reinterpret_cast<const uint8_t *>(buffer + sizeof(packet->packetType) + sizeof(packet->success) + sizeof(packet->rsaPublicKey));

    packet->packetType = *packetType;
    packet->success = *success;
    memcpy(&packet->rsaPublicKey, rsaPublicKey, sizeof(packet->rsaPublicKey));
    memcpy(&packet->aesKey, aesKey, sizeof(packet->aesKey));
}
