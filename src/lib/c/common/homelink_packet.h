#ifndef HOMELINK_PACKET_H
#define HOMELINK_PACKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

    typedef enum LoginStatus
    {
        e_LoginFailed = 0,
        e_LoginSuccess = 1,
        e_NoSuchService = 2
    } LoginStatus;

    typedef enum RegisterStatus
    {
        e_RegisterFailed = 0,
        e_RegisterSuccess = 1,
        e_AlreadyExists = 2
    } RegisterStatus;

    typedef enum HomeLinkPacketType
    {
        e_Ack = 1,
        e_KeyRequest = 2,
        e_KeyResponse = 3,
        e_Handshake = 4,
        e_Command = 5,
        e_LoginRequest = 6,
        e_LoginResponse = 7,
        e_RegisterRequest = 8,
        e_RegisterResponse = 9,
        e_Logout = 10,
        e_AsyncNotification = 11
    } HomeLinkPacketType;

    typedef enum RegistrationType
    {
        e_HostRegistration = 1,
        e_ServiceRegistration = 2
    } RegistrationType;

    typedef enum AsyncEventType
    {
        e_FileEvent = 1
    } AsyncEventType;

    // UDP
    typedef struct PingPacket
    {
        uint8_t packetType;
        uint32_t value;
    } PingPacket;
    extern const int32_t PingPacket_SIZE;
    void PingPacket_serialize(uint8_t *buffer, const PingPacket *packet);
    void PingPacket_deserialize(PingPacket *packet, const uint8_t *buffer);

    // UDP
    typedef struct AckPacket
    {
        uint8_t packetType;
        uint32_t value;
    } AckPacket;
    extern const int32_t AckPacket_SIZE;
    void AckPacket_serialize(uint8_t *buffer, const AckPacket *packet);
    void AckPacket_deserialize(AckPacket *packet, const uint8_t *buffer);

    // UDP
    typedef struct KeyRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char rsaPublicKey[512];
    } KeyRequestPacket;
    extern const int32_t KeyRequestPacket_SIZE;
    void KeyRequestPacket_serialize(uint8_t *buffer,
                                    const KeyRequestPacket *packet);
    void KeyRequestPacket_deserialize(KeyRequestPacket *packet,
                                      const uint8_t *buffer);

    // UDP
    typedef struct KeyResponsePacket
    {
        uint8_t packetType;
        uint8_t success;
        char rsaPublicKey[512];
        uint8_t aesKey[256];
    } KeyResponsePacket;
    extern const int32_t KeyResponsePacket_SIZE;
    void KeyResponsePacket_serialize(uint8_t *buffer,
                                     const KeyResponsePacket *packet);
    void KeyResponsePacket_deserialize(KeyResponsePacket *packet,
                                       const uint8_t *buffer);

    // TCP
    typedef struct CommandPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        uint8_t sessionToken[256];
        uint8_t data[256];
    } CommandPacket;
    extern const int32_t CommandPacket_SIZE;
    void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet);
    void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer);

    // UDP
    typedef struct LoginRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char hostId[33];
        char serviceId[33];
        uint8_t data[256];
    } LoginRequestPacket;
    extern const int32_t LoginRequestPacket_SIZE;
    void LoginRequestPacket_serialize(uint8_t *buffer,
                                      const LoginRequestPacket *packet);
    void LoginRequestPacket_deserialize(LoginRequestPacket *packet,
                                        const uint8_t *buffer);

    // UDP
    typedef struct LoginResponsePacket
    {
        uint8_t packetType;
        uint8_t status;
        uint8_t sessionKey[256];
    } LoginResponsePacket;
    extern const int32_t LoginResponsePacket_SIZE;
    void LoginResponsePacket_serialize(uint8_t *buffer,
                                       const LoginResponsePacket *packet);
    void LoginResponsePacket_deserialize(LoginResponsePacket *packet,
                                         const uint8_t *buffer);

    // UDP
    typedef struct RegisterRequestPacket
    {
        uint8_t packetType;
        uint8_t registrationType;
        char hostId[33];
        char serviceId[33];
        uint8_t data[256];
    } RegisterRequestPacket;
    extern const int32_t RegisterRequestPacket_SIZE;
    void RegisterRequestPacket_serialize(uint8_t *buffer,
                                         const RegisterRequestPacket *packet);
    void RegisterRequestPacket_deserialize(RegisterRequestPacket *packet,
                                           const uint8_t *buffer);

    // UDP
    typedef struct RegisterResponsePacket
    {
        uint8_t packetType;
        uint8_t status;
    } RegisterResponsePacket;
    extern const int32_t RegisterResponsePacket_SIZE;
    void RegisterResponsePacket_serialize(uint8_t *buffer,
                                          const RegisterResponsePacket *packet);
    void RegisterResponsePacket_deserialize(RegisterResponsePacket *packet,
                                            const uint8_t *buffer);

    // UDP
    typedef struct LogoutPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        uint8_t sessionKey[256];
    } LogoutPacket;
    extern const int32_t LogoutPacket_SIZE;
    void LogoutPacket_serialize(uint8_t *buffer, const LogoutPacket *packet);
    void LogoutPacket_deserialize(LogoutPacket *packet, const uint8_t *buffer);

    typedef struct AsyncNotificationPacket
    {
        uint8_t packetType;
        uint8_t eventType;
        int32_t tag;
    } AsyncNotificationPacket;
    extern const int32_t AsyncNotificationPacket_SIZE;
    void AsyncNotificationPacket_serialize(uint8_t *buffer, const AsyncNotificationPacket *packet);
    void AsyncNotificationPacket_deserialize(AsyncNotificationPacket *packet, const uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif
