/*
20140727
Jan Mojzis
Public domain.
*/

#include "cleanup.h"
#include "salsa.h"

int crypto_stream_xsalsa20_tinynacl_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    unsigned char subkey[32];
    long long i;

    salsa_hash(subkey, n, k, 20);
    salsa_stream_xor(c, m, l, n + 16, subkey, 20);
    cleanup(subkey);
    return 0;
}

int crypto_stream_xsalsa20_tinynacl(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    return crypto_stream_xsalsa20_tinynacl_xor(c, 0, l, n, k);
}
