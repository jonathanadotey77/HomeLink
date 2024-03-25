#include <homelink_security.h>

#include <openssl/rand.h>

static bool randInitialized = false;

void randomBytes(uint8_t *buffer, int n)
{

    if (!randInitialized)
    {
        RAND_poll();
        randInitialized = true;
    }
    RAND_bytes(buffer, n);
}