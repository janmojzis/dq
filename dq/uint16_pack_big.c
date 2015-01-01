#include "uint16_pack_big.h"

void uint16_pack_big(unsigned char *y, crypto_uint16 x) {

    y[1] = x & 255; x >>= 8;
    y[0] = x & 255;
}
