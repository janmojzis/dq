/*
20141017
Jan Mojzis
Public domain.
*/

#include "misc.h"
#include "crypto_secretbox_xsalsa20poly1305.h"

#define SPACESIZE 5232

static unsigned char m[SPACESIZE + 16];
static unsigned char k[crypto_secretbox_xsalsa20poly1305_KEYBYTES + 16];
static unsigned char n[crypto_secretbox_xsalsa20poly1305_NONCEBYTES + 16];
static unsigned char c[SPACESIZE + 16 + crypto_secretbox_xsalsa20poly1305_ZEROBYTES];

static unsigned char test_pseudorandom_checksum[32] = {
    0xfa, 0x3e, 0x24, 0x31, 0x6d, 0xd4, 0x77, 0x76, 
    0xa8, 0x94, 0x71, 0x63, 0x25, 0xaa, 0xb7, 0x4f, 
    0x17, 0xfb, 0x28, 0xfe, 0xc4, 0x57, 0xe7, 0x3f, 
    0x22, 0x1f, 0xf3, 0x06, 0xc3, 0x98, 0x45, 0x89
};


static void zerobytes(void *yv, long long ylen) {

    long long i;
    char *y = yv;

    for (i = 0; i < ylen; ++i) y[i] = 0;
}



static void test_pseudorandom(void) {

    long long i, j;

    checksum_zero();
    i = 0;
    for (j = crypto_secretbox_xsalsa20poly1305_ZEROBYTES; j < SPACESIZE; j += 1 + j / 16) {

        pseudorandombytes(m + i, j);
        pseudorandombytes(k + i  , crypto_secretbox_xsalsa20poly1305_KEYBYTES);
        pseudorandombytes(n + i, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
        zerobytes(m + i, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

        crypto_secretbox_xsalsa20poly1305(c + i, m + i, j, n, k + i);
        checksum(c + i, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
    
        zerobytes(c + i, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
        if (crypto_secretbox_xsalsa20poly1305_open(m + i, c + i, j, n, k + i) != 0) {
            fail_printdata("m", m + i, j);
            fail_printdata("c", c + i, j);
            fail_printdata("k", k + i, crypto_secretbox_xsalsa20poly1305_KEYBYTES);
            fail_printdata("n", n + i, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
            fail("crypto_secretbox_xsalsa20poly1305_open() failure");
        }
        ++i;
        i %= 16;
    }
    fail_whenbadchecksum(test_pseudorandom_checksum);
}


int main(void) {

    test_pseudorandom();

    _exit(0);
}
