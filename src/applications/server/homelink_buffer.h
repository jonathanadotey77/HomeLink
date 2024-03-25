#ifndef HOMELINK_BUFFER_H
#define HOMELINK_BUFFER_H

#include <iostream>
#include <string.h>
#include <stdint.h>

class Buffer
{
private:
    uint8_t *buffer;
    size_t len;

public:
    Buffer(size_t len=512);
    Buffer(const uint8_t *src, size_t len);
    Buffer(const Buffer &other);

    Buffer &operator=(const Buffer &other);

    ~Buffer();

    size_t size() const;

    uint8_t *data();
    const uint8_t *data() const;
    void zero();
    void init(size_t len);
    std::string toString() const;

    uint8_t &operator[](size_t i);
    const uint8_t &operator[](size_t i) const;
    Buffer operator^(const Buffer &other);
    Buffer &operator^=(const Buffer &other);
    bool operator==(const Buffer &other);

private:
    void copy(const Buffer &other);
};

std::ostream &operator<<(std::ostream &os, const Buffer &buffer);

#endif