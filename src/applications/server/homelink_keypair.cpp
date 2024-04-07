#include <homelink_keypair.h>

#include <homelink_security.h>

#include <string.h>
#include <vector>

KeyPair::KeyPair()
{
    this->rsaPublicKey = new char[1];
    this->aesKey = new uint8_t[1];
    this->ctx = EVP_CIPHER_CTX_new();
}

KeyPair::KeyPair(const char *rsaPublicKey, size_t rsaPublicKeyLen)
{
    this->rsaPublicKey = new char[rsaPublicKeyLen + 1];
    this->rsaPublicKeyLen = rsaPublicKeyLen;
    strncpy(this->rsaPublicKey, rsaPublicKey, rsaPublicKeyLen);
    this->rsaPublicKey[this->rsaPublicKeyLen] = '\0';
    this->aesKey = new uint8_t[AES_KEY_LEN / 8];
    generateAESKey(aesKey, AES_KEY_LEN);
    this->ctx = EVP_CIPHER_CTX_new();
}

KeyPair::~KeyPair()
{
    delete[] this->aesKey;
    delete[] this->rsaPublicKey;
    EVP_CIPHER_CTX_free(this->ctx);
}

void KeyPair::initializeEncrypt(const uint8_t *iv)
{
    EVP_EncryptInit_ex(this->ctx, EVP_aes_256_gcm(), NULL, this->aesKey, iv);
}

void KeyPair::initializeDecrypt(const uint8_t *iv)
{
    EVP_DecryptInit_ex(this->ctx, EVP_aes_256_gcm(), NULL, this->aesKey, iv);
}

void KeyPair::encryptAES(uint8_t *out, size_t outLen, const uint8_t *in, size_t inLen) const
{
}
void KeyPair::decryptAES(uint8_t *out, size_t outLen, const uint8_t *in, size_t inLen) const
{
}

void KeyPair::encryptRSA(uint8_t *out, size_t outLen, const uint8_t *in, size_t inLen) const
{
}