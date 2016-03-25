/*
20160325
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include "randombytes.h"
#include "writeall.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

static unsigned char pk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
static unsigned char sk[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
static unsigned char nk[16];

static char buf[256];
static long long buflen = 0;

static void flush(void) {

    if (writeall(1, buf, buflen) == -1) _exit(111);
    buflen = 0;
}

static void outs(const char *x) {

    long long i;

    for(i = 0; x[i]; ++i) {
        if (buflen >= sizeof buf) flush();
        buf[buflen++] = x[i];
    }
}

static void out(const char *x, long long len) {

    long long i;

    for(i = 0; i < len; ++i) {
        if (buflen >= sizeof buf) flush();
        buf[buflen++] = x[i];
    }
}


int main(int argc, char **argv) {

    long long i;
    char ch;

    crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk);
    randombytes(nk, sizeof nk);
    outs("PUBLICKEY=");
    for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES; ++i) {
        ch = "0123456789abcdef"[15 & (int) (pk[i] >> 4)]; out(&ch, 1);
        ch = "0123456789abcdef"[15 & (int) (pk[i] >> 0)]; out(&ch, 1);
    }
    outs("\n");
    outs("SECRETKEY=");
    for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES; ++i) {
        ch = "0123456789abcdef"[15 & (int) (sk[i] >> 4)]; out(&ch, 1);
        ch = "0123456789abcdef"[15 & (int) (sk[i] >> 0)]; out(&ch, 1);
    }
    outs("\n");
    outs("NONCEKEY=");
    for (i = 0; i < 16; ++i) {
        ch = "0123456789abcdef"[15 & (int) (nk[i] >> 4)]; out(&ch, 1);
        ch = "0123456789abcdef"[15 & (int) (nk[i] >> 0)]; out(&ch, 1);
    }
    outs("\n");
    flush();
    _exit(0);
}
