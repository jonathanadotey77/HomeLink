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
        e_LoginResponse = 6,
        e_RegisterRequest = 7,
        e_RegisterResponse = 8
    };

    // UDP localhost only
    typedef struct CLIPacket
    {
        uint8_t packetType;
        char rsaPublicKey[512];
        char data[256];
    } CLIPacket;
    extern const int32_t CLIPacket_SIZE;
    void CLIPacket_serialize(uint8_t *buffer, const CLIPacket *packet);
    void CLIPacket_deserialize(CLIPacket *packet, const uint8_t *buffer);

    typedef struct AckPacket
    {
        uint8_t packetType;
        uint32_t value;
    } AckPacket;
    extern const int32_t AckPacket_SIZE;
    void AckPacket_serialize(uint8_t *buffer, const AckPacket *packet);
    void AckPacket_deserialize(AckPacket *packet, const uint8_t *buffer);

    typedef struct KeyRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char rsaPublicKey[512];
    } KeyRequestPacket;
    extern const int32_t KeyRequestPacket_SIZE;
    void KeyRequestPacket_serialize(uint8_t *buffer, const KeyRequestPacket *packet);
    void KeyRequestPacket_deserialize(KeyRequestPacket *packet, const uint8_t *buffer);

    typedef struct KeyResponsePacket
    {
        uint8_t packetType;
        uint8_t success;
        char rsaPublicKey[512];
        uint8_t aesKey[256];
    } KeyResponsePacket;
    extern const int32_t KeyResponsePacket_SIZE;
    void KeyResponsePacket_serialize(uint8_t *buffer, const KeyResponsePacket *packet);
    void KeyResponsePacket_deserialize(KeyResponsePacket *packet, const uint8_t *buffer);

    typedef struct CommandPacket
    {
        uint8_t packetType;
        uint8_t sessionToken[256];
        uint8_t data[256];
    } CommandPacket;
    extern const int32_t CommandPacket_SIZE;
    void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet);
    void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer);

    typedef struct LoginRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char hostId[33];
        char serviceId[33];
        uint8_t data[256];
    } LoginRequestPacket;
    extern const int32_t LoginRequestPacket_SIZE;
    void LoginRequestPacket_serialize(uint8_t *buffer, const LoginRequestPacket *packet);
    void LoginRequestPacket_deserialize(LoginRequestPacket *packet, const uint8_t *buffer);

    typedef struct LoginResponsePacket
    {
        uint8_t packetType;
        uint8_t status;
        uint8_t sessionKey[256];
    } LoginResponsePacket;
    extern const int32_t LoginResponsePacket_SIZE;
    void LoginResponsePacket_serialize(uint8_t *buffer, const LoginResponsePacket *packet);
    void LoginResponsePacket_deserialize(LoginResponsePacket *packet, const uint8_t *buffer);

    typedef struct RegisterRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char hostId[33];
        char serviceId[33];
        uint8_t data[256];
    } RegisterRequestPacket;
    extern const int32_t RegisterRequestPacket_SIZE;
    void RegisterRequestPacket_serialize(uint8_t *buffer, const RegisterRequestPacket *packet);
    void RegisterRequestPacket_deserialize(RegisterRequestPacket *packet, const uint8_t *buffer);

    typedef struct RegisterResponsePacket
    {
        uint8_t packetType;
        uint8_t status;
    } RegisterResponsePacket;
    extern const int32_t RegisterResponsePacket_SIZE;
    void RegisterResponsePacket_serialize(uint8_t *buffer, const RegisterResponsePacket *packet);
    void RegisterResponsePacket_deserialize(RegisterResponsePacket *packet, const uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif
