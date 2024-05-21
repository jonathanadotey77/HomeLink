#ifndef HOMELINK_AESKEY_H
#define HOMELINK_AESKEY_H

#include <cstddef>
#include <cstdint>

class AesKey
{
private:
    size_t keySize;
    size_t keySizeInBytes;
    uint8_t *aesKey;

public:
    AesKey();
    // The keySize parameter is in bits, not bytes
    AesKey(size_t keySize);
    AesKey(const AesKey &other);
    ~AesKey();

    AesKey &operator=(const AesKey &other);

    const uint8_t *data() const;

private:
    void copy(const AesKey &other);
    void destroy();
};

#endif
