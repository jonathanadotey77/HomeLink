#ifndef HOMELINK_LOGINSTATUS_H
#define HOMELINK_LOGINSTATUS_H

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum LoginStatus
    {
        e_LoginFailed = 0,
        e_LoginSuccess = 1,
        e_NoAvailablePort = 2,
        e_NoSuchUser = 3,
        e_UserAlreadyExists = 4
    } LoginStatus;

#ifdef __cplusplus
}
#endif

#endif
