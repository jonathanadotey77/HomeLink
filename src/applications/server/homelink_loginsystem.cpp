#include <homelink_loginsystem.h>

#include <homelink_misc.h>
#include <homelink_security.h>

#include <string.h>

typedef struct LoginStruct
{
    LoginStatus status; // 0 if user not found; 1 if login success; 2 if incorrect password
    const char *password;
} LoginStruct;

static int loginCallback(void *data, int, char **argv, char **)
{
    LoginStruct *loginStruct = static_cast<LoginStruct *>(data);

    const char *password = argv[0];
    const char *salt = argv[1];

    char *saltedPassword = saltedHash(loginStruct->password, strlen(loginStruct->password), salt, strlen(salt));

    if (std::string(saltedPassword) == std::string(password))
    {
        loginStruct->status = LoginStatus::e_LoginSuccess;
    }
    else
    {
        loginStruct->status = LoginStatus::e_LoginFailed;
    }

    free(saltedPassword);

    return 0;
}

const std::string LoginSystem::LOGIN_FILE = std::string(getenv("HOMELINK_ROOT")) + "/login/login.db";
bool LoginSystem::start()
{
    int rc = sqlite3_open(LOGIN_FILE.c_str(), &dbHandle);
    if (rc)
    {
        fprintf(stderr, "Couldn't open database\n");
        sqlite3_close(dbHandle);
        return false;
    }
    char *error = NULL;

    const char *sql = "CREATE TABLE IF NOT EXISTS USERS ("
                      "username TEXT PRIMARY KEY,"
                      "password TEXT NOT NULL,"
                      "salt TEXT NOT NULL);";
    sqlite3_exec(dbHandle, sql, NULL, NULL, &error);
    if (error)
    {
        fprintf(stderr, "|%s|\n", error);

        return false;
    }

    return true;
}

void LoginSystem::stop()
{
    sqlite3_close(dbHandle);
}

LoginStatus LoginSystem::tryLogin(const char *username, const char *password)
{
    char sql[512] = {0};
    snprintf(sql, sizeof(sql), "SELECT password, salt FROM USERS WHERE username = '%s';", username);
    LoginStruct loginStruct;
    loginStruct.status = LoginStatus::e_NoSuchUser;
    loginStruct.password = password;
    sqlite3_exec(dbHandle, sql, loginCallback, &loginStruct, NULL);

    LoginStatus status = loginStruct.status;

    memset(sql, 0, sizeof(sql));
    memset(&loginStruct, 0, sizeof(loginStruct));

    return status;
}

LoginStatus LoginSystem::registerUser(const char *username, const char *password)
{
    LoginStatus rc = this->tryLogin(username, password);
    if (rc != e_NoSuchUser)
    {
        return LoginStatus::e_UserAlreadyExists;
    }

    uint8_t salt[16] = {0};
    randomBytes(salt, 16);
    char saltStr[sizeof(salt) * 2 + 1];
    getByteStr(saltStr, salt, sizeof(salt));
    saltStr[sizeof(saltStr)-1] = '\0';

    char* saltedPassword = saltedHash(password, strlen(password), saltStr, sizeof(saltStr)-1);

    char sql[512] = {0};

    snprintf(sql, sizeof(sql), "INSERT INTO USERS (username, password, salt) VALUES ('%s', '%s', '%s')", username, saltedPassword, saltStr);
    sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
    memset(sql, 0, sizeof(sql));
    memset(salt, 0, sizeof(salt));
    memset(saltStr, 0, sizeof(saltStr));

    free(saltedPassword);

    return LoginStatus::e_LoginSuccess;
}

LoginStatus LoginSystem::changePassword(const char *username,
                                        const char *oldPassword,
                                        const char *newPassword)
{
    LoginStatus rc = this->tryLogin(username, oldPassword);
    if (rc == e_LoginFailed || rc == e_NoSuchUser)
    {
        return rc;
    }

    char sql[512] = {0};

    uint8_t salt[16] = {0};
    randomBytes(salt, 16);
    char saltStr[sizeof(salt) * 2 + 1];
    getByteStr(saltStr, salt, sizeof(salt));
    saltStr[sizeof(saltStr)-1] = '\0';

    char* saltedPassword = saltedHash(newPassword, strlen(newPassword), saltStr, sizeof(saltStr)-1);

    snprintf(sql, sizeof(sql), "UPDATE USERS SET password = '%s', salt = '%s' WHERE username = '%s';", saltedPassword, saltStr, username);
    sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
    memset(sql, 0, sizeof(sql));

    free(saltedPassword);

    return LoginStatus::e_LoginSuccess;
}
