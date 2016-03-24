/*
20140727
Jan Mojzis
Public domain.
*/

#include "crypto_core_hsalsa20.h"
#include "crypto_stream_salsa20.h"
#include "cleanup.h"
#include "crypto_stream_xsalsa20.h"

static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_stream_xsalsa20_tinynacl_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    unsigned char subkey[32];

    crypto_core_hsalsa20(subkey, n, k, sigma);
    crypto_stream_salsa20_xor(c, m, l, n + 16, subkey);
    cleanup(subkey);
    return 0;
}

int crypto_stream_xsalsa20_tinynacl(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    return crypto_stream_xsalsa20_tinynacl_xor(c, 0, l, n, k);
}
