#ifndef HOMELINK_KEYSET_H
#define HOMELINK_KEYSET_H

#include <homelink_buffer.h>

#include <vector>

class KeySet
{
private:

    size_t numKeys;
    std::vector<Buffer> keys;
    size_t current;

public:
    KeySet(size_t numKeys=0, size_t keySize=512);

    void init(size_t numKeys, size_t keySize);

    void nextKey();

    const Buffer& getCurrent() const;
    size_t size() const;
    const Buffer& operator[](size_t i) const;
};

#endif