#ifndef HOMELINK_LOGINSYSTEM_H
#define HOMELINK_LOGINSYSTEM_H

#include <homelink_packet.h>

#include <fstream>
#include <sqlite3.h>
#include <string>

// SINGLETON
class LoginSystem
{
private:
    static const std::string LOGIN_FILE;
    static int validateHostCallback(void *data, int, char **argv, char **);

private:
    sqlite3 *dbHandle;

private:
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

private:
    LoginSystem() {}

    // Deleted copy constructor and assignment operator.
    LoginSystem(const LoginSystem &other) = delete;
    LoginSystem &operator=(const LoginSystem &other) = delete;

    HostValidationStatus validateHostKey(const char *hostId, const char *hostKey);

public:
    // Returns Singleton instance.
    static LoginSystem *getInstance();

    // Initializes sqlite login database.
    bool start();

    // Closes the database connection.
    void stop();

    // Returns the result of login.
    LoginStatus tryLogin(const char *hostId, const char *serviceId,
                         const char *hostKey, const char *password);

    // Attempts to register a host.
    RegisterStatus registerHost(const char *hostId, const char *hostKey);

    // Attempts to register a service.
    RegisterStatus registerService(const char *hostId, const char *serviceId,
                                   const char *hostKey, const char *password);

    // Currently unused.
    LoginStatus changePassword(const char *hostId, const char *serviceId,
                               const char *hostKey, const char *oldPassword,
                               const char *newPassword);
};

#endif
