/*
20140709
Jan Mojzis
Public domain.
*/

#include "misc.h"
#include "crypto_core_salsa20.h"

unsigned char key[crypto_core_salsa20_KEYBYTES + 16];
unsigned char out[crypto_core_salsa20_OUTPUTBYTES + 16];
unsigned char in[crypto_core_salsa20_INPUTBYTES + 16];
unsigned char c[crypto_core_salsa20_CONSTBYTES + 16];

unsigned char o[32] = {
    0xd6, 0x44, 0x5b, 0x27, 0x0c, 0xac, 0x03, 0x79, 
    0x60, 0xa9, 0x31, 0x5a, 0x92, 0xb7, 0x5a, 0x6f, 
    0xaa, 0x10, 0x2f, 0x96, 0x9a, 0xe9, 0xcc, 0x2b, 
    0x72, 0x35, 0xd9, 0x99, 0x8f, 0x22, 0x02, 0xcf
};

void test_alignment(void) {

    long long i;

    for (i = 0; i < 16; ++i) {
        crypto_core_salsa20(out + i, in + i, key + i, c + i);
    }
}

static void test_rand(void) {

    long long i;

    for (i = 0; i < 256; ++i) {
        pseudorandombytes(key, sizeof key);
        pseudorandombytes(in, sizeof in);
        crypto_core_salsa20(out, in, key, sigma);
        checksum(out, crypto_core_salsa20_OUTPUTBYTES);
    }
    fail_whenbadchecksum(o);
}

int main(void) {

    test_alignment();
    test_rand();

    _exit(0);
}
