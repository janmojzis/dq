#include "crypto_onetimeauth_poly1305.h"
#include "crypto_stream_xsalsa20.h"
#include "crypto_secretbox_xsalsa20poly1305.h"

int crypto_secretbox_xsalsa20poly1305_tinynacl(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k) {

    long long i;
    if (mlen < 32) return -1;
    crypto_stream_xsalsa20_xor(c, m, mlen, n, k);
    crypto_onetimeauth_poly1305(c + 16, c + 32, mlen - 32, c);
    for (i = 0; i < 16; ++i) c[i] = 0;
    return 0;
}

int crypto_secretbox_xsalsa20poly1305_tinynacl_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) {

    long long i;
    unsigned char subkey[32];
    if (clen < 32) return -1;
    crypto_stream_xsalsa20(subkey, 32, n, k);
    if (crypto_onetimeauth_poly1305_verify(c + 16, c + 32, clen - 32, subkey) != 0) return -1;
    crypto_stream_xsalsa20_xor(m, c, clen, n, k);
    for (i = 0; i < 32; ++i) m[i] = 0;
    return 0;
}
