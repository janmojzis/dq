/*
20140709
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include "misc.h"
#include "crypto_stream_xsalsa20.h"

static unsigned char space[5232];
static unsigned char k[crypto_stream_xsalsa20_KEYBYTES + 16];
static unsigned char n[crypto_stream_xsalsa20_NONCEBYTES + 16];

static unsigned char o[32] = {
    0x6b, 0x76, 0xcf, 0xe5, 0x1b, 0x44, 0x3d, 0x93, 
    0xda, 0x0d, 0xee, 0x1d, 0x0b, 0xac, 0xfa, 0xfe, 
    0x2d, 0x55, 0x3d, 0x9a, 0x3c, 0x1e, 0x19, 0xb9, 
    0xe1, 0x0e, 0x3f, 0x78, 0x2d, 0xc3, 0x68, 0xf1
};

static void test_alignment(void) {

    long long i;

    for (i = 0; i < 16; ++i) {
        crypto_stream_xsalsa20_xor(space + i, space + i, sizeof space - i, n + i, k + i);
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
        crypto_stream_xsalsa20_xor(space, space, i, n, k);
    }
    checksum(space, sizeof space);
    fail_whenbadchecksum(o);
}


int main(void) {

    test_alignment();
    test_rand();
    _exit(0);
}
