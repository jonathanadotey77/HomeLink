#include <homelink_aeskey.h>

#include <homelink_security.h>

AesKey::AesKey()
{
    this->keySize = 8;
    this->keySizeInBytes = this->keySize / 8;
    if (this->keySize % 8 != 0)
    {
        ++this->keySizeInBytes;
    }

    this->aesKey = new uint8_t[this->keySizeInBytes];
    randomBytes(this->aesKey, this->keySizeInBytes);
}

AesKey::AesKey(size_t keySize)
{
    this->keySize = keySize;
    this->keySizeInBytes = this->keySize / 8;
    if (this->keySize % 8 != 0)
    {
        ++this->keySizeInBytes;
    }

    this->aesKey = new uint8_t[this->keySizeInBytes];
    randomBytes(this->aesKey, this->keySizeInBytes);
}

AesKey::AesKey(const AesKey &other)
{
    this->copy(other);
}

AesKey::~AesKey()
{
    this->destroy();
}

AesKey &AesKey::operator=(const AesKey &other)
{
    if (this != &other)
    {
        this->destroy();
        this->copy(other);
    }

    return *this;
}

const uint8_t *AesKey::data() const
{
    return this->aesKey;
}

void AesKey::copy(const AesKey &other)
{
    this->keySize = other.keySize;
    this->keySizeInBytes = other.keySizeInBytes;
    this->aesKey = new uint8_t[this->keySizeInBytes];

    for (size_t i = 0; i < this->keySizeInBytes; ++i)
    {
        this->aesKey[i] = other.aesKey[i];
    }
}
void AesKey::destroy()
{
    for (size_t i = 0; i < this->keySizeInBytes; ++i)
    {
        this->aesKey[i] = 0;
    }

    delete[] this->aesKey;
}
