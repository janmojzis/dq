/*
20141018
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <unistd.h>
#include "randombytes.h"
#include "nanoseconds.h"
#include "uint32_pack_big.h"
#include "crypto.h"
#include "fastrandombytes.h"

void fastrandombytes(void *x, long long xlen) {

    /*
    Fast pseudorandom byte-stream using crypto_stream_salsa20.
    Cryptographically secure across fork(), but not thread-safe.
    */
    unsigned char nonce[8];
    static unsigned char key[64];
    static crypto_uint32 counter = 0;

    if (xlen <= 0) return;
    if (!counter) {
        randombytes(key, 64);
        uint32_pack_big(nonce    , nanoseconds());
        uint32_pack_big(nonce + 4, getppid());
        crypto_stream_salsa20(key, 64, nonce, key + 32);
    }
    uint32_pack_big(nonce    , counter++);
    uint32_pack_big(nonce + 4, getpid());
    crypto_stream_salsa20((unsigned char *)x, xlen, nonce, key);
    uint32_pack_big(nonce    , nanoseconds());
    crypto_stream_salsa20(key, 64, nonce, key + 32);
}
