#include "salsa.h"
#include "uint32_unpack.h"
#include "cleanup.h"
#include "crypto_core_hsalsa20.h"

int crypto_core_hsalsa20_tinynacl(unsigned char *o, const unsigned char *nn, const unsigned char *kk, const unsigned char *cc) {

    crypto_uint32 k[8], n[4], c[4];
    long long i;

    for (i = 0; i < 8; ++i) k[i] = uint32_unpack(kk + 4 * i);
    for (i = 0; i < 4; ++i) n[i] = uint32_unpack(nn + 4 * i);
    for (i = 0; i < 4; ++i) c[i] = uint32_unpack(cc + 4 * i);

    salsa_core(o, n, k, c, 1, 20);
    cleanup(k); cleanup(n); cleanup(c);
    return 0;
}
