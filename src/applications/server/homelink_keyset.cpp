#include <homelink_keyset.h>

#include <homelink_aeskey.h>
#include <homelink_misc.h>
#include <homelink_security.h>

#include <stdint.h>
#include <string.h>
#include <vector>

KeySet::KeySet()
{
    this->rsaPublicKey = new char[1];
    this->rsaPublicKeyLen = 1;

    this->aesKey = AesKey(8);

    this->ctx = EVP_CIPHER_CTX_new();
}

KeySet::KeySet(const KeySet &other) { this->copy(other); }

KeySet::KeySet(const char *rsaPublicKey, size_t rsaPublicKeyLen)
{
    this->rsaPublicKey = new char[rsaPublicKeyLen + 1];
    memset(this->rsaPublicKey, 0, rsaPublicKeyLen + 1);
    this->rsaPublicKeyLen = rsaPublicKeyLen;
    strncpy(this->rsaPublicKey, rsaPublicKey, rsaPublicKeyLen);

    this->aesKey = AesKey(AES_KEY_SIZE);
    this->ctx = EVP_CIPHER_CTX_new();
}

KeySet::~KeySet() { this->destroy(); }

KeySet &KeySet::operator=(const KeySet &other)
{
    if (this != &other)
    {
        this->destroy();
        this->copy(other);
    }

    return *this;
}

void KeySet::setUser(const char *hostId, const char *serviceId)
{
    this->hostId = std::string(hostId);
    this->serviceId = std::string(serviceId);
}

bool KeySet::checkTag(uint64_t tag) { return this->tags.insert(tag).second; }

bool KeySet::validSessionKey(const char *key) const
{
    return this->sessionKeys.find(std::string(key)) != sessionKeys.end();
}

const char *KeySet::newSessionKey()
{
    uint8_t key[16] = {0};
    randomBytes(key, sizeof(key));
    char keyStr[sizeof(key) * 2 + 16] = {0};
    getByteStr(keyStr, key, sizeof(key));
    std::pair<std::unordered_set<std::string>::iterator, bool> p =
        this->sessionKeys.insert(std::string(keyStr));
    const char *out = NULL;
    if (p.second == true)
    {
        out = p.first->c_str();
    }
    else
    {
        out = newSessionKey();
    }

    memset(key, 0, sizeof(key));
    memset(keyStr, 0, sizeof(keyStr));

    return out;
}

const char *KeySet::getPublicKey() const { return this->rsaPublicKey; }

void KeySet::copy(const KeySet &other)
{
    this->aesKey = other.aesKey;
    this->rsaPublicKeyLen = other.rsaPublicKeyLen;
    this->rsaPublicKey = new char[this->rsaPublicKeyLen + 1];
    memcpy(this->rsaPublicKey, other.rsaPublicKey, this->rsaPublicKeyLen + 1);

    this->ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_copy(this->ctx, other.ctx);
}

void KeySet::destroy()
{
    delete[] this->rsaPublicKey;
    EVP_CIPHER_CTX_free(this->ctx);
}

const AesKey &KeySet::getAesKey() const
{
    return this->aesKey;
}

const std::string &KeySet::getHostId() const { return this->hostId; }
const std::string &KeySet::getServiceId() const { return this->serviceId; }
