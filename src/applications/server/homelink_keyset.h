#ifndef HOMELINK_KEYSET_H
#define HOMELINK_KEYSET_H

#include <homelink_aeskey.h>
#include <homelink_security.h>

#include <openssl/evp.h>
#include <stdint.h>
#include <string>
#include <unordered_set>
#include <vector>

class KeySet
{
private:
    AesKey aesKey;

    char *rsaPublicKey;
    size_t rsaPublicKeyLen;

    EVP_CIPHER_CTX *ctx;

    std::unordered_set<uint64_t> tags;
    std::unordered_set<std::string> sessionKeys;

    std::string hostId;
    std::string serviceId;

public:
    KeySet();
    KeySet(const KeySet &other);
    KeySet(const char *rsaPublicKey, size_t rsaPublicKeyLen);
    ~KeySet();

    KeySet &operator=(const KeySet &other);

    // Attemps to insert the tag into the internal set. Returns
    // true if successful. This is essential for preventing replay
    // attacks.
    bool checkTag(uint64_t tag);

    // Attaches a hostId and serviceId to the KeySet
    void setUser(const char *hostId, const char *serviceId);

    // Returns true if the session key was previously generated.
    bool validSessionKey(const char *key) const;

    // Returns a new session key, the key is stored in an internal
    // set.
    const char *newSessionKey();

    // Returns the associated RSA public key.
    const char *getPublicKey() const;

    // Returns the associated AES key.
    const AesKey &getAesKey() const;

    // Returns the hostId if it was set, and an empty string
    // otherwise.
    const std::string &getHostId() const;

    // Returns the hostId if it was set, and an empty string
    // otherwise.
    const std::string &getServiceId() const;

private:
    // Deep copy.
    void copy(const KeySet &other);

    // For destructor.
    void destroy();
};

#endif
