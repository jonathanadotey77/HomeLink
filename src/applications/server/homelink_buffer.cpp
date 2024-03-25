#include <homelink_buffer.h>
#include <homelink_misc.h>

#include <algorithm>

Buffer::Buffer(size_t len)
{
    this->len = len;
    this->buffer = new uint8_t[this->len];
    this->zero();
}
Buffer::Buffer(const uint8_t *src, size_t len)
{
    this->len = len;
    this->buffer = new uint8_t[len];
    for (size_t i = 0; i < this->len; ++i)
    {
        this->buffer[i] = src[i];
    }
}

Buffer::Buffer(const Buffer &other)
{
    this->copy(other);
}

Buffer &Buffer::operator=(const Buffer &other)
{
    if (this != &other)
    {
        delete[] this->buffer;
        this->copy(other);
    }

    return *this;
}

void Buffer::copy(const Buffer &other)
{
    this->len = other.len;
    this->buffer = new uint8_t[this->len];

    memcpy(this->buffer, other.buffer, this->len);
}

Buffer::~Buffer()
{
    delete[] this->buffer;
}

size_t Buffer::size() const
{
    return this->len;
}

uint8_t *Buffer::data()
{
    return this->buffer;
}

const uint8_t *Buffer::data() const
{
    return this->buffer;
}

void Buffer::zero()
{
    memset(this->buffer, 0, this->len);
}

void Buffer::init(size_t len)
{
    delete[] this->buffer;
    this->buffer = new uint8_t[len];
}

std::string Buffer::toString() const
{
    std::string out;
    char* buffer = new char[this->len * 4];
    getByteStr(buffer, this->buffer, this->len);

    delete[] buffer;

    return out;
}

uint8_t &Buffer::operator[](size_t i)
{
    return this->buffer[i];
}

const uint8_t &Buffer::operator[](size_t i) const
{
    return this->buffer[i];
}

Buffer Buffer::operator^(const Buffer &other)
{
    size_t newLen = std::min(this->len, other.len);
    Buffer newBuffer(newLen);

    for (size_t i = 0; i < newLen; ++i)
    {
        newBuffer[i] = this->buffer[i] ^ other.buffer[i];
    }

    return newBuffer;
}

Buffer &Buffer::operator^=(const Buffer &other)
{
    size_t newLen = std::min(this->len, other.len);
    uint8_t *newBuffer = new uint8_t[newLen];
    for (size_t i = 0; i < newLen; ++i)
    {
        newBuffer[i] = this->buffer[i] ^ other.buffer[i];
    }

    delete[] this->buffer;
    this->buffer = newBuffer;

    return *this;
}

bool Buffer::operator==(const Buffer &other)
{
    if (this->len != other.len)
    {
        return false;
    }

    for (size_t i = 0; i < this->len; ++i)
    {
        if (this->buffer[i] != other.buffer[i])
        {
            return false;
        }
    }

    return true;
}

std::ostream &operator<<(std::ostream &os, const Buffer &buffer)
{
    os << buffer.toString();

    return os;
}