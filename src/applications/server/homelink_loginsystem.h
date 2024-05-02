#ifndef HOMELINK_LOGINSYSTEM_H
#define HOMELINK_LOGINSYSTEM_H

#include <homelink_packet.h>

#include <fstream>
#include <sqlite3.h>
#include <string>

class LoginSystem
{
private:
    static const std::string LOGIN_FILE;
    static int validateHostCallback(void *data, int, char **argv, char **);
    sqlite3 *dbHandle;

    LoginSystem() {}
    LoginSystem(const LoginSystem &other);
    LoginSystem &operator=(const LoginSystem &other);

    typedef enum HostValidationStatus
    {
        e_HostValidationFailed = 0,
        e_HostValidationSuccess = 1,
        e_NoSuchHost = 2
    } HostValidationStatus;

    typedef struct ValidateHostStruct
    {
        HostValidationStatus status;
        const char *hostKey;
    } ValidateHostStruct;

    HostValidationStatus validateHostKey(const char *hostId, const char *hostKey);

public:
    static LoginSystem &getInstance();

    bool start();

    void stop();

    LoginStatus tryLogin(const char *hostId, const char *serviceId,
                         const char *hostKey, const char *password);

    RegisterStatus registerHost(const char *hostId, const char *hostKey);

    RegisterStatus registerService(const char *hostId, const char *serviceId,
                                   const char *hostKey, const char *password);

    LoginStatus changePassword(const char *hostId, const char *serviceId,
                               const char *hostKey, const char *oldPassword,
                               const char *newPassword);
};

#endif