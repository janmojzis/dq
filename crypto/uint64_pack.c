#include "uint64_pack.h"

/*
The 'uint64_pack' function converts 64-bit unsigned
integer into 8 bytes stored in little-endian format
*/
void uint64_pack(unsigned char *y, crypto_uint64 x) {

    long long i;
    for (i = 0; i < 8; ++i) { y[i] = x; x >>= 8; }
}
