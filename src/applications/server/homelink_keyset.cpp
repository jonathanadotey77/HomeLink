#include <homelink_keyset.h>

#include <homelink_misc.h>
#include <homelink_security.h>

#include <stdint.h>
#include <string.h>
#include <vector>

KeySet::KeySet()
{
    this->rsaPublicKey = new char[1];
    this->rsaPublicKeyLen = 0;

    this->aesKey = new uint8_t[1];
    this->aesKeyLen = 0;

    this->ctx = EVP_CIPHER_CTX_new();

}

KeySet::KeySet(const KeySet& other) {
    this->copy(other);
}

KeySet::KeySet(const char *rsaPublicKey, size_t rsaPublicKeyLen)
{
    this->rsaPublicKey = new char[rsaPublicKeyLen + 1];
    memset(this->rsaPublicKey, 0, rsaPublicKeyLen + 1);
    this->rsaPublicKeyLen = rsaPublicKeyLen;
    strncpy(this->rsaPublicKey, rsaPublicKey, rsaPublicKeyLen);

    this->aesKey = new uint8_t[AES_KEY_LEN / 8];
    this->aesKeyLen = AES_KEY_LEN / 8;
    generateAESKey(aesKey, AES_KEY_LEN);
    this->ctx = EVP_CIPHER_CTX_new();
}

KeySet::~KeySet()
{
    this->destroy();
}

KeySet& KeySet::operator=(const KeySet& other) {
    if(this != &other) {
        this->destroy();
        this->copy(other);
    }

    return *this;
}

bool KeySet::checkTag(uint32_t tag)
{
    return this->tags.insert(tag).second;
}

bool KeySet::validSessionKey(const char *key) const
{
    return this->sessionKeys.find(std::string(key)) != sessionKeys.end();
}

const char *KeySet::newSessionKey()
{
    uint8_t key[16] = {0};
    randomBytes(key, sizeof(key));
    char keyStr[sizeof(key) * 2 + 1] = {0};
    getByteStr(keyStr, key, sizeof(key));
    std::pair<std::unordered_set<std::string>::iterator, bool> p = this->sessionKeys.insert(std::string(keyStr));
    const char* out = NULL;
    if(p.second == true) {
        out = p.first->c_str();
    } else {
        out = newSessionKey();
    }

    memset(key, 0, sizeof(key));
    memset(keyStr, 0, sizeof(keyStr));

    return out;
}

const char* KeySet::getPublicKey() const {
    return this->rsaPublicKey;
}

void KeySet::copy(const KeySet& other) {
    this->aesKeyLen = other.aesKeyLen;
    this->aesKey = new uint8_t[this->aesKeyLen];
    memcpy(this->aesKey, other.aesKey, this->aesKeyLen);

    this->rsaPublicKeyLen = other.rsaPublicKeyLen;
    this->rsaPublicKey = new char[this->rsaPublicKeyLen+1];
    memcpy(this->rsaPublicKey, other.rsaPublicKey, this->rsaPublicKeyLen+1);

    this->ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_copy(this->ctx, other.ctx);
}

void KeySet::destroy() {
    delete[] this->aesKey;
    delete[] this->rsaPublicKey;
    EVP_CIPHER_CTX_free(this->ctx);
}
