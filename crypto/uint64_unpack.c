#include "order.h"
#include "uint64_unpack.h"

/*
The 'uint64_unpack' function converts 8 bytes
in little-endian format into 64-bit unsigned integer.
*/
crypto_uint64 uint64_unpack(const unsigned char *x) {

#ifdef ORDER_LITTLEENDIAN
    return *(crypto_uint64 *)x;
#else
    crypto_uint64 y = 0;
    long long i;
    for (i = 7; i >= 0; --i) y = (y << 8) | x[i];
    return y;
#endif
}
