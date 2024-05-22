#include <homelink_loginsystem.h>

#include <homelink_misc.h>
#include <homelink_security.h>

#include <filesystem>
#include <mutex>
#include <string.h>

typedef struct LoginStruct
{
    LoginStatus status;
    const char *password;
} LoginStruct;

int LoginSystem::validateHostCallback(void *data, int, char **argv, char **)
{
    ValidateHostStruct *validateHostStruct =
        static_cast<ValidateHostStruct *>(data);

    const char *password = argv[0];
    const char *salt = argv[1];

    char *saltedPassword =
        saltedHash(validateHostStruct->hostKey,
                   strlen(validateHostStruct->hostKey), salt, strlen(salt));

    if (std::string(saltedPassword) == std::string(password))
    {
        validateHostStruct->status = e_HostValidationSuccess;
    }
    else
    {
        validateHostStruct->status = e_HostValidationFailed;
    }

    memset(saltedPassword, 0, strlen(saltedPassword));
    free(saltedPassword);

    return 0;
}

static int loginCallback(void *data, int, char **argv, char **)
{
    LoginStruct *loginStruct = static_cast<LoginStruct *>(data);

    const char *storedPassword = argv[0];
    const char *salt = argv[1];

    char *saltedPassword = saltedHash(
        loginStruct->password, strlen(loginStruct->password), salt, strlen(salt));

    if (std::string(saltedPassword) == std::string(storedPassword))
    {
        loginStruct->status = LoginStatus::e_LoginSuccess;
    }
    else
    {
        loginStruct->status = LoginStatus::e_LoginFailed;
    }

    memset(saltedPassword, 0, strlen(saltedPassword));
    free(saltedPassword);

    return 0;
}

const std::string LoginSystem::LOGIN_FILE = std::string(getenv("HOMELINK_ROOT")) + "/login/login.db";

static std::mutex loginSystemLock;
static volatile bool active = false;

LoginSystem *LoginSystem::getInstance()
{
    static LoginSystem instance;
    return &instance;
}
bool LoginSystem::start()
{
    loginSystemLock.lock();
    FILE *fp = fopen(LOGIN_FILE.c_str(), "rb");
    if (fp == NULL)
    {
        fp = fopen(LOGIN_FILE.c_str(), "wb");
        fclose(fp);
    }
    else
    {
        fclose(fp);
    }
    int rc = sqlite3_open(LOGIN_FILE.c_str(), &dbHandle);
    if (rc)
    {
        fprintf(stderr, "Couldn't open database\n");
        sqlite3_close(dbHandle);
        loginSystemLock.unlock();
        return false;
    }
    char *error = NULL;

    const char *sql = "CREATE TABLE IF NOT EXISTS HOSTS("
                      "hostId TEXT NOT NULL, "
                      "password TEXT NOT NULL, "
                      "salt TEXT NOT NULL, "
                      "PRIMARY KEY (hostId)"
                      "); "
                      "CREATE TABLE IF NOT EXISTS SERVICES ("
                      "hostId TEXT NOT NULL, "
                      "serviceId TEXT NOT NULL, "
                      "password TEXT NOT NULL, "
                      "salt TEXT NOT NULL, "
                      "PRIMARY KEY (hostId, serviceID), "
                      "FOREIGN KEY (hostId) REFERENCES HOSTS(hostId)"
                      ");";
    sqlite3_exec(dbHandle, sql, NULL, NULL, &error);
    if (error)
    {
        fprintf(stderr, "|%s|\n", error);
        loginSystemLock.unlock();
        return false;
    }

    active = true;
    loginSystemLock.unlock();
    return true;
}

void LoginSystem::stop()
{
    loginSystemLock.lock();
    sqlite3_close(dbHandle);
    active = false;
    loginSystemLock.unlock();
}

LoginSystem::HostValidationStatus
LoginSystem::validateHostKey(const char *hostId, const char *hostKey)
{
    char sql[512] = {0};
    snprintf(sql, sizeof(sql) - 1,
             "SELECT password, salt FROM HOSTS WHERE hostId = '%s';", hostId);
    ValidateHostStruct validateHostStruct;
    validateHostStruct.status = e_NoSuchHost;
    validateHostStruct.hostKey = hostKey;

    loginSystemLock.lock();
    sqlite3_exec(dbHandle, sql, validateHostCallback, &validateHostStruct, NULL);
    loginSystemLock.unlock();

    return validateHostStruct.status;
}

LoginStatus LoginSystem::tryLogin(const char *hostId, const char *serviceId,
                                  const char *hostKey, const char *password)
{
    if (this->validateHostKey(hostId, hostKey) != e_HostValidationSuccess)
    {
        return e_LoginFailed;
    }
    char sql[512] = {0};
    snprintf(sql, sizeof(sql),
             "SELECT password, salt FROM SERVICES WHERE hostId = '%s' and serviceId "
             "= '%s';",
             hostId, serviceId);
    LoginStruct loginStruct;
    loginStruct.status = LoginStatus::e_NoSuchService;
    loginStruct.password = password;
    loginSystemLock.lock();
    sqlite3_exec(dbHandle, sql, loginCallback, &loginStruct, NULL);
    loginSystemLock.unlock();

    LoginStatus status = loginStruct.status;

    memset(sql, 0, sizeof(sql));
    memset(&loginStruct, 0, sizeof(loginStruct));
    printf("Status: %d\n", (int)status);

    return status;
}

RegisterStatus LoginSystem::registerHost(const char *hostId,
                                         const char *hostKey)
{
    HostValidationStatus rc = this->validateHostKey(hostId, hostKey);
    if (rc != e_NoSuchHost)
    {
        if (rc == e_HostValidationSuccess)
        {
            return e_AlreadyExists;
        }
        return e_RegisterFailed;
    }

    uint8_t salt[16] = {0};
    randomBytes(salt, 16);
    char saltStr[sizeof(salt) * 2 + 1];
    getByteStr(saltStr, salt, sizeof(salt));
    saltStr[sizeof(saltStr) - 1] = '\0';

    char *saltedHostKey =
        saltedHash(hostKey, strlen(hostKey), saltStr, sizeof(saltStr) - 1);

    char sql[512] = {0};

    snprintf(sql, sizeof(sql),
             "INSERT INTO HOSTS (hostId, password, salt) VALUES "
             "('%s', '%s', '%s')",
             hostId, saltedHostKey, saltStr);
    loginSystemLock.lock();
    sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
    loginSystemLock.unlock();
    memset(sql, 0, sizeof(sql));
    memset(salt, 0, sizeof(salt));
    memset(saltStr, 0, sizeof(saltStr));

    free(saltedHostKey);

    return RegisterStatus::e_RegisterSuccess;
}

RegisterStatus LoginSystem::registerService(const char *hostId,
                                            const char *serviceId,
                                            const char *hostKey,
                                            const char *password)
{
    LoginStatus rc = this->tryLogin(hostId, serviceId, hostKey, password);
    if (rc != e_NoSuchService)
    {
        if (rc == e_LoginSuccess)
        {
            return e_AlreadyExists;
        }
        return e_RegisterFailed;
    }

    uint8_t salt[16] = {0};
    randomBytes(salt, sizeof(salt));
    char saltStr[sizeof(salt) * 2 + 1];
    getByteStr(saltStr, salt, sizeof(salt));
    saltStr[sizeof(saltStr) - 1] = '\0';

    char *saltedPassword =
        saltedHash(password, strlen(password), saltStr, sizeof(saltStr) - 1);

    char sql[512] = {0};

    snprintf(sql, sizeof(sql),
             "INSERT INTO SERVICES (hostId, serviceId, password, salt) VALUES "
             "('%s', '%s', '%s', '%s')",
             hostId, serviceId, saltedPassword, saltStr);
    loginSystemLock.lock();
    sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
    loginSystemLock.unlock();
    memset(sql, 0, sizeof(sql));
    memset(salt, 0, sizeof(salt));
    memset(saltStr, 0, sizeof(saltStr));

    free(saltedPassword);

    return RegisterStatus::e_RegisterSuccess;
}

LoginStatus LoginSystem::changePassword(const char *hostId,
                                        const char *serviceId,
                                        const char *hostKey,
                                        const char *oldPassword,
                                        const char *newPassword)
{
    LoginStatus rc = this->tryLogin(hostId, serviceId, hostKey, oldPassword);
    if (rc == e_LoginFailed || rc == e_NoSuchService)
    {
        return rc;
    }

    char sql[512] = {0};

    uint8_t salt[16] = {0};
    randomBytes(salt, 16);
    char saltStr[sizeof(salt) * 2 + 1];
    getByteStr(saltStr, salt, sizeof(salt));
    saltStr[sizeof(saltStr) - 1] = '\0';

    char *saltedPassword = saltedHash(newPassword, strlen(newPassword), saltStr,
                                      sizeof(saltStr) - 1);

    snprintf(sql, sizeof(sql) - 1,
             "UPDATE SERVICES SET password = '%s', salt = '%s' WHERE hostId = '%s' "
             "and serviceId = '%s';",
             saltedPassword, saltStr, hostId, serviceId);
    loginSystemLock.lock();
    sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
    loginSystemLock.unlock();
    memset(sql, 0, sizeof(sql));

    free(saltedPassword);

    return LoginStatus::e_LoginSuccess;
}
