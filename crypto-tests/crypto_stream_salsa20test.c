/*
20140709
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include "misc.h"
#include "crypto_stream_salsa20.h"

static unsigned char space[5232];
static unsigned char k[crypto_stream_salsa20_KEYBYTES + 16];
static unsigned char n[crypto_stream_salsa20_NONCEBYTES + 16];

static unsigned char o[32] = {
    0x09, 0x96, 0x21, 0xd0, 0xa4, 0x0c, 0x75, 0x0d,
    0xdb, 0x4c, 0x03, 0xaf, 0xe9, 0xe0, 0xf4, 0x3e,
    0xa1, 0x82, 0x5a, 0x36, 0x41, 0x62, 0x49, 0x08,
    0x65, 0xeb, 0x2f, 0x3d, 0x14, 0x1f, 0xc3, 0x37
};

static void test_alignment(void) {

    long long i;

    for (i = 0; i < 16; ++i) {
        crypto_stream_salsa20_xor(space + i, space + i, sizeof space - i, n + i, k + i);
    }
}

static void test_rand(void) {

    long long i, j;
    unsigned int u;

    pseudorandombytes(space, sizeof space);
    pseudorandombytes(k, sizeof k);
    pseudorandombytes(n, sizeof n);

    for (i = 0; i < sizeof space; i += 1 + i / 16) {
        u = 1;
        for (j = 0; j < 8; ++j) {
            u += (unsigned int) n[j];
            n[j] = u;
            u >>= 8;
        }
        crypto_stream_salsa20_xor(space, space, i, n, k);
    }
    checksum(space, sizeof space);
    fail_whenbadchecksum(o);
}


int main(void) {

    test_alignment();
    test_rand();
    _exit(0);
}
