#include <homelink_keyset.h>
#include <homelink_security.h>

#include <vector>

KeySet::KeySet(size_t numKeys, size_t keySize)
{
    this->numKeys = numKeys;

    this->keys = std::vector<Buffer>(numKeys, Buffer(keySize));

    for (size_t i = 0; i < this->keys.size(); ++i)
    {
        randomBytes(this->keys[i].data(), keySize);
    }
}

size_t KeySet::size() const
{
    return this->numKeys;
}

const Buffer &KeySet::operator[](size_t i) const
{
    return this->keys[i];
}