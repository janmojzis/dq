#include "crypto.h"
#include "randombytes.h"
#include "uint32_pack.h"
#include "nanoseconds.h"
#include "dns.h"  

void dns_keys(unsigned char *pk, unsigned char *sk, unsigned char *nk) {

    unsigned char seed[64];
    long long i;

    randombytes(seed, 64);
    uint32_pack(seed, nanoseconds());
    crypto_hash_sha512(seed, seed, 64);

    for (i = 0; i < 32; ++i) sk[i] = seed[i     ];
    for (i = 0; i < 16; ++i) nk[i] = seed[i + 32];
    crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk);
    for (i = 0; i < 64; ++i) seed[i] = 0;
}
