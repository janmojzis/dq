#include "crypto.h"
#include "randombytes.h"
#include "dns.h"  

void dns_keys(unsigned char *pk, unsigned char *sk, unsigned char *nk) {

    randombytes(nk, 16);
    crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk);
}
