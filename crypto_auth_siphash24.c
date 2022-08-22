#include "siphash.h"
#include "crypto_verify_8.h"
#include "crypto_auth_siphash24.h"

int crypto_auth_siphash24_tinynacl(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) {
    return siphash(out, in, inlen, k, 2, 4);
}

int crypto_auth_siphash24_tinynacl_verify(const unsigned char *h, const unsigned char *m, unsigned long long n, const unsigned char *k) {

    unsigned char x[8];
    crypto_auth_siphash24_tinynacl(x, m, n, k);
    return crypto_verify_8(h, x);
}
