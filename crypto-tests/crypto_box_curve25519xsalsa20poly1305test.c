/*
20141017
Jan Mojzis
Public domain.
*/

#include "misc.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

#define SPACESIZE 5232

static unsigned char m[SPACESIZE + 16];
static unsigned char n[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES + 16];
static unsigned char c[SPACESIZE + 16 + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES];
static unsigned char pk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES + 16];
static unsigned char sk[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES + 16];

static unsigned char test_pseudorandom_checksum[32] = {
    0xb7, 0xd4, 0xf1, 0x92, 0x3d, 0x4b, 0x80, 0xf0, 
    0xb5, 0x3c, 0xdb, 0x38, 0xdb, 0x53, 0xcf, 0xb6, 
    0xe8, 0x3d, 0x52, 0x96, 0xb6, 0x73, 0x61, 0x07, 
    0x95, 0x72, 0x37, 0x69, 0xad, 0xda, 0x65, 0x8b
};


static void zerobytes(void *yv, long long ylen) {

    long long i;
    char *y = yv;

    for (i = 0; i < ylen; ++i) y[i] = 0;
}


static void copy(void *yv, long long ylen, const void *xv) {

    long long i;
    const char *x = xv;
    char *y = yv;

    for (i = 0; i < ylen; ++i) y[i] = x[i];
}


static unsigned char skdata[1080][32] = {
#include "precomp.data"
};

static unsigned char pkdata[1080][32] = {
#include "precomp_curve25519.data"
};


static void test_pseudorandom(void) {

    long long i, j;

    checksum_zero();
    i = 0;
    for (j = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES; j < SPACESIZE; j += 1 + j / 16) {

        pseudorandombytes(m + i, j);
        pseudorandombytes(n + i, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
        zerobytes(m + i, crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);

        copy(sk + i, 32, skdata[i]);
        copy(pk + i, 32, pkdata[i]);

        crypto_box_curve25519xsalsa20poly1305(c + i, m + i, j, n, pk + i, sk + i);
        checksum(c + i, crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
    
        zerobytes(c + i, crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
        if (crypto_box_curve25519xsalsa20poly1305_open(m + i, c + i, j, n, pk + i, sk + i) != 0) {
            fail_printdata("m", m + i, j);
            fail_printdata("c", c + i, j);
            fail_printdata("pk", pk + i, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
            fail_printdata("sk", sk + i, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
            fail_printdata("n", n + i, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
            fail("crypto_box_curve25519xsalsa20poly1305_open() failure");
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
