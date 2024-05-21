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
        e_Ping = 1,
        e_ConnectionRequest = 2,
        e_ConnectionResponse = 3,
        e_Handshake = 4,
        e_Command = 5,
        e_LoginRequest = 6,
        e_LoginResponse = 7,
        e_RegisterRequest = 8,
        e_RegisterResponse = 9,
        e_Logout = 10,
        e_AsyncListenRequest = 11,
        e_AsyncNotification = 12
    } HomeLinkPacketType;

    typedef enum RegistrationType
    {
        e_HostRegistration = 1,
        e_ServiceRegistration = 2
    } RegistrationType;

    typedef enum AsyncEventType
    {
        e_FileEvent = 1,
        e_AnyEvent = 255
    } AsyncEventType;

    extern const char *getPacketStr(HomeLinkPacketType packetType);

    typedef struct PingPacket
    {
        uint8_t packetType;
        uint32_t value;
    } PingPacket;
    extern const char *PingPacket_STR;
    extern const int32_t PingPacket_SIZE;
    extern void PingPacket_serialize(uint8_t *buffer, const PingPacket *packet);
    extern void PingPacket_deserialize(PingPacket *packet, const uint8_t *buffer);

    typedef struct ConnectionRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char rsaPublicKey[512];
    } ConnectionRequestPacket;
    extern const char *ConnectionRequestPacket_STR;
    extern const int32_t ConnectionRequestPacket_SIZE;
    extern void ConnectionRequestPacket_serialize(uint8_t *buffer,
                                                  const ConnectionRequestPacket *packet);
    extern void ConnectionRequestPacket_deserialize(ConnectionRequestPacket *packet,
                                                    const uint8_t *buffer);

    typedef struct ConnectionResponsePacket
    {
        uint8_t packetType;
        uint8_t success;
        char rsaPublicKey[512];
        uint8_t aesKey[256];
    } ConnectionResponsePacket;
    extern const char *ConnectionResponsePacket_STR;
    extern const int32_t ConnectionResponsePacket_SIZE;
    extern void ConnectionResponsePacket_serialize(uint8_t *buffer,
                                                   const ConnectionResponsePacket *packet);
    extern void ConnectionResponsePacket_deserialize(ConnectionResponsePacket *packet,
                                                     const uint8_t *buffer);

    typedef struct CommandPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        uint8_t sessionKey[80];
        uint8_t data[256];
    } CommandPacket;
    extern const char *CommandPacket_STR;
    extern const int32_t CommandPacket_SIZE;
    extern void CommandPacket_serialize(uint8_t *buffer, const CommandPacket *packet);
    extern void CommandPacket_deserialize(CommandPacket *packet, const uint8_t *buffer);

    typedef struct LoginRequestPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        char hostId[33];
        char serviceId[33];
        uint8_t data[256];
    } LoginRequestPacket;
    extern const char *LoginRequestPacket_STR;
    extern const int32_t LoginRequestPacket_SIZE;
    extern void LoginRequestPacket_serialize(uint8_t *buffer,
                                             const LoginRequestPacket *packet);
    extern void LoginRequestPacket_deserialize(LoginRequestPacket *packet,
                                               const uint8_t *buffer);

    typedef struct LoginResponsePacket
    {
        uint8_t packetType;
        uint8_t status;
        uint8_t sessionKey[80];
    } LoginResponsePacket;
    extern const char *LoginResponsePacket_STR;
    extern const int32_t LoginResponsePacket_SIZE;
    extern void LoginResponsePacket_serialize(uint8_t *buffer,
                                              const LoginResponsePacket *packet);
    extern void LoginResponsePacket_deserialize(LoginResponsePacket *packet,
                                                const uint8_t *buffer);

    typedef struct RegisterRequestPacket
    {
        uint8_t packetType;
        uint8_t registrationType;
        char hostId[33];
        char serviceId[33];
        uint8_t data[256];
    } RegisterRequestPacket;
    extern const char *RegisterRequestPacket_STR;
    extern const int32_t RegisterRequestPacket_SIZE;
    extern void RegisterRequestPacket_serialize(uint8_t *buffer,
                                                const RegisterRequestPacket *packet);
    extern void RegisterRequestPacket_deserialize(RegisterRequestPacket *packet,
                                                  const uint8_t *buffer);

    typedef struct RegisterResponsePacket
    {
        uint8_t packetType;
        uint8_t status;
    } RegisterResponsePacket;
    extern const char *RegisterResponsePacket_STR;
    extern const int32_t RegisterResponsePacket_SIZE;
    extern void RegisterResponsePacket_serialize(uint8_t *buffer,
                                                 const RegisterResponsePacket *packet);
    extern void RegisterResponsePacket_deserialize(RegisterResponsePacket *packet,
                                                   const uint8_t *buffer);

    typedef struct LogoutPacket
    {
        uint8_t packetType;
        uint32_t connectionId;
        uint8_t sessionKey[80];
    } LogoutPacket;
    extern const char *LogoutPacket_STR;
    extern const int32_t LogoutPacket_SIZE;
    extern void LogoutPacket_serialize(uint8_t *buffer, const LogoutPacket *packet);
    extern void LogoutPacket_deserialize(LogoutPacket *packet, const uint8_t *buffer);

    typedef struct AsyncListenRequestPacket
    {
        uint8_t packetType;
        uint8_t eventType;
        uint32_t connectionId;
        uint8_t sessionKey[80];
    } AsyncListenRequestPacket;
    extern const char *AsyncListenRequestPacket_STR;
    extern const int32_t AsyncListenRequestPacket_SIZE;
    extern void AsyncListenRequestPacket_serialize(uint8_t *buffer, const AsyncListenRequestPacket *packet);
    extern void AsyncListenRequestPacket_deserialize(AsyncListenRequestPacket *packet, const uint8_t *buffer);

    typedef struct AsyncNotificationPacket
    {
        uint8_t packetType;
        uint8_t eventType;
        int32_t tag;
    } AsyncNotificationPacket;
    extern const char *AsyncNotificationPacket_STR;
    extern const int32_t AsyncNotificationPacket_SIZE;
    extern void AsyncNotificationPacket_serialize(uint8_t *buffer, const AsyncNotificationPacket *packet);
    extern void AsyncNotificationPacket_deserialize(AsyncNotificationPacket *packet, const uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif
