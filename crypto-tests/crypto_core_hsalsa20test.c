/*
20140709
Jan Mojzis
Public domain.
*/

#include "misc.h"
#include "crypto_core_hsalsa20.h"

static unsigned char key[crypto_core_hsalsa20_KEYBYTES + 16];
static unsigned char out[crypto_core_hsalsa20_OUTPUTBYTES + 16];
static unsigned char in[crypto_core_hsalsa20_INPUTBYTES + 16];
static unsigned char c[crypto_core_hsalsa20_CONSTBYTES + 16];

static unsigned char o[32] = {
    0xe4, 0x28, 0xb8, 0xc2, 0x3a, 0xda, 0x66, 0x8b, 
    0x9b, 0x55, 0xdb, 0x31, 0xdf, 0x9c, 0x6d, 0x80, 
    0x4a, 0x31, 0x5b, 0x72, 0x07, 0xb9, 0x2f, 0x3a, 
    0xc5, 0x94, 0x27, 0x87, 0x4d, 0x47, 0xfa, 0xb1
};

static void test_alignment(void) {

    long long i;

    for (i = 0; i < 16; ++i) {
        crypto_core_hsalsa20(out + i, in + i, key + i, c + i);
    }
}

static void test_rand(void) {

    long long i;

    for (i = 0; i < 256; ++i) {
        pseudorandombytes(key, sizeof key);
        pseudorandombytes(in, sizeof in);
        crypto_core_hsalsa20(out, in, key, sigma);
        checksum(out, crypto_core_hsalsa20_OUTPUTBYTES);
    }
    fail_whenbadchecksum(o);
}

int main(void) {

    test_alignment();
    test_rand();

    _exit(0);
}
