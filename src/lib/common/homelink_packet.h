#ifndef HOMELINK_PACKET_H
#define HOMELINK_PACKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

    enum HomeLinkPacketType
    {
        e_CLI = 255,
        e_Ack = 0,
        e_KeyRequest = 1,
        e_KeyResponse = 2,
        e_Handshake = 3,
        e_Command
    };

    // UDP localhost only
    typedef struct CLIPacket
    {
        uint8_t packetType;
        char rsaPublicKey[512];
        char data[256];
    } CLIPacket;
    const uint32_t CLIPacket_SIZE = sizeof(((CLIPacket){0}).packetType) + sizeof(((CLIPacket){0}).rsaPublicKey) + sizeof(((CLIPacket){0}).data);
    void CLIPacket_serialize(uint8_t *buffer, const CLIPacket *packet);
    void CLIPacket_deserialize(CLIPacket *packet, const uint8_t *buffer);

    typedef struct AckPacket
    {
        uint8_t packetType;
        uint32_t value;
    } AckPacket;
    const uint32_t AckPacket_SIZE = sizeof(((AckPacket){0}).packetType) + sizeof(((AckPacket){0}).value);
    void AckPacket_serialize(uint8_t *buffer, const AckPacket *packet);
    void AckPacket_deserialize(AckPacket *packet, const uint8_t *buffer);

    typedef struct KeyRequestPacket
    {
        uint8_t packetType;
        uint32_t keysetId;
        char rsaPublicKey[512];
    } KeyRequestPacket;
    const uint32_t KeyRequestPacket_SIZE = sizeof(((KeyRequestPacket){0}).packetType) + sizeof(((KeyRequestPacket){0}).keysetId) + sizeof(((KeyRequestPacket){0}).rsaPublicKey);
    void KeyRequestPacket_serialize(uint8_t *buffer, const KeyRequestPacket *packet);
    void KeyRequestPacket_deserialize(KeyRequestPacket *packet, const uint8_t *buffer);

    // For TCP
    typedef struct KeyResponsePacket
    {
        uint8_t packetType;
        uint8_t success;
        char rsaPublicKey[512];
        uint8_t aesKey[32];
    } KeyResponsePacket;
    const uint32_t KeyResponsePacket_SIZE = sizeof(((KeyResponsePacket){0}).packetType) + sizeof(((KeyResponsePacket){0}).success) + sizeof(((KeyResponsePacket){0}).rsaPublicKey) + sizeof(((KeyResponsePacket){0}).aesKey);
    void KeyResponsePacket_serialize(uint8_t *buffer, const KeyResponsePacket *packet);
    void KeyResponsePacket_deserialize(KeyResponsePacket *packet, const uint8_t *buffer);

    typedef struct CommandPacket
    {
        uint8_t packetType;
        char command[12];
        uint8_t data[400];
    } CommandPacket;
    const uint32_t CommandPacket_SIZE = sizeof(((CommandPacket){0}).packetType) + sizeof(((CommandPacket){0}).command) + sizeof(((CommandPacket){0}).data);
    void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet);
    void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif
