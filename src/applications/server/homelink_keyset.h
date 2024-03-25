#ifndef HOMELINK_KEYSET_H
#define HOMELINK_KEYSET_H

#include <homelink_buffer.h>

#include <vector>

class KeySet
{
private:

    size_t numKeys;
    std::vector<Buffer> keys;

public:
    KeySet(size_t numKeys, size_t keySize);

    size_t size() const;

    const Buffer& operator[](size_t i) const;
};

#endif