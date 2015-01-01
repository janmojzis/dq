#include "uint16_unpack_big.h"

crypto_uint16 uint16_unpack_big(const unsigned char *x) {

    crypto_uint16 y;

    y  = x[0]; y <<= 8;
    y |= x[1];

    return y;
}
