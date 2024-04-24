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
    sqlite3 *dbHandle;

public:
    LoginSystem() {}

    bool start();

    void stop();

    LoginStatus tryLogin(const char *hostId, const char *serviceId, const char *password);

    LoginStatus registerUser(const char *hostId, const char *serviceId, const char *password);

    LoginStatus changePassword(const char *hostId, const char *serviceId,
                               const char *oldPassword,
                               const char *newPassword);
};

#endif