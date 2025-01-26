#include "salsa.h"
#include "crypto_uint32.h"
#include "cleanup.h"
#include "crypto_core_hsalsa20.h"

int crypto_core_hsalsa20_tinynacl(unsigned char *o, const unsigned char *nn, const unsigned char *kk, const unsigned char *cc) {

    crypto_uint32 k[8], n[4], c[4];
    long long i;

    for (i = 0; i < 8; ++i) k[i] = crypto_uint32_load(kk + 4 * i);
    for (i = 0; i < 4; ++i) n[i] = crypto_uint32_load(nn + 4 * i);
    for (i = 0; i < 4; ++i) c[i] = crypto_uint32_load(cc + 4 * i);

    salsa_core(o, n, k, c, 1, 20);
    return 0;
}
