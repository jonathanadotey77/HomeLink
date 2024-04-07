#ifndef HOMELINK_KEYPAIR_H
#define HOMELINK_KEYPAIR_H

#include <homelink_security.h>

#include <openssl/evp.h>
#include <stdint.h>
#include <vector>

// Pair of keys
// AES key and client's RSA public key

static const size_t AES_KEY_LEN = 256;
class KeyPair
{
private:

    uint8_t* aesKey;
    char* rsaPublicKey;
    size_t rsaPublicKeyLen;
    EVP_CIPHER_CTX* ctx;

public:

    KeyPair();
    KeyPair(const char* rsaPublicKey, size_t rsaPublicKeyLen);
    ~KeyPair();

    void initializeEncrypt(const uint8_t* iv);
    void initializeDecrypt(const uint8_t* iv);

    void encryptAES(uint8_t* out, size_t outLen, const uint8_t* in, size_t inLen) const;
    void decryptAES(uint8_t* out, size_t outLen, const uint8_t* in, size_t inLen) const;

    void encryptRSA(uint8_t* out, size_t outLen, const uint8_t* in, size_t inLen) const;
};

#endif