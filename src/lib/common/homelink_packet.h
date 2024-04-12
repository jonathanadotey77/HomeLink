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
        e_Command = 4,
        e_LoginRequest = 5,
        e_LoginResponse = 6
    };

    // UDP localhost only
    typedef struct CLIPacket
    {
        uint8_t packetType;
        char rsaPublicKey[512];
        char data[256];
    } CLIPacket;
    extern const uint32_t CLIPacket_SIZE;
    void CLIPacket_serialize(uint8_t *buffer, const CLIPacket *packet);
    void CLIPacket_deserialize(CLIPacket *packet, const uint8_t *buffer);

    typedef struct AckPacket
    {
        uint8_t packetType;
        uint32_t value;
    } AckPacket;
    extern const uint32_t AckPacket_SIZE;
    void AckPacket_serialize(uint8_t *buffer, const AckPacket *packet);
    void AckPacket_deserialize(AckPacket *packet, const uint8_t *buffer);

    typedef struct KeyRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char rsaPublicKey[512];
    } KeyRequestPacket;
    extern const uint32_t KeyRequestPacket_SIZE;
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
    extern const uint32_t KeyResponsePacket_SIZE;
    void KeyResponsePacket_serialize(uint8_t *buffer, const KeyResponsePacket *packet);
    void KeyResponsePacket_deserialize(KeyResponsePacket *packet, const uint8_t *buffer);

    typedef struct CommandPacket
    {
        uint8_t packetType;
        uint8_t sessionToken[64];
        char command[12];
        uint8_t data[400];
    } CommandPacket;
    extern const uint32_t CommandPacket_SIZE;
    void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet);
    void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer);

    typedef struct LoginRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char username[33];
        uint8_t salt[64];
        uint8_t password[128];
    } LoginRequestPacket;
    extern const uint32_t LoginRequestPacket_SIZE;
    void LoginRequestPacket_serialize(uint8_t *buffer, const LoginRequestPacket *packet);
    void LoginRequestPacket_deserialize(LoginRequestPacket *packet, const uint8_t *buffer);

    typedef struct LoginResponsePacket
    {
        uint8_t packetType;
        uint8_t sessionToken[32];
    } LoginResponsePacket;
    extern const uint32_t LoginResponsePacket_SIZE;
    void LoginResponsePacket_serialize(uint8_t *buffer, const LoginResponsePacket *packet);
    void LoginResponsePacket_deserialize(LoginResponsePacket *packet, const uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif