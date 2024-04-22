#ifndef HOMELINK_KEYSET_H
#define HOMELINK_KEYSET_H

#include <homelink_security.h>

#include <openssl/evp.h>
#include <stdint.h>
#include <string>
#include <unordered_set>
#include <vector>

static const size_t AES_KEY_LEN = 256;
class KeySet
{
private:
    uint8_t *aesKey;
    size_t aesKeyLen;

    char *rsaPublicKey;
    size_t rsaPublicKeyLen;
    
    EVP_CIPHER_CTX *ctx;

    std::unordered_set<uint32_t> tags;
    std::unordered_set<std::string> sessionKeys;

    std::string hostId;
    std::string serviceId;

public:
    KeySet();
    KeySet(const KeySet& other);
    KeySet(const char *rsaPublicKey, size_t rsaPublicKeyLen);
    ~KeySet();

    KeySet& operator=(const KeySet& other);

    bool checkTag(uint32_t tag);
    void setUser(const char* hostId, const char* serviceId);

    bool validSessionKey(const char* key) const;
    const char* newSessionKey();
    const char* getPublicKey() const;
    uint8_t* getAesKey() const;

    const std::string& getHostId() const;
    const std::string& getServiceId() const;

private:

    void copy(const KeySet& other);
    void destroy();
};

#endif
