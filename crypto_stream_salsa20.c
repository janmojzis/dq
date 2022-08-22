/*
20140727
Jan Mojzis
Public domain.
*/

#include "salsa.h"
#include "crypto_stream_salsa20.h"

int crypto_stream_salsa20_tinynacl_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {
    return salsa_stream_xor(c, m, l, n, k, 20);
}

int crypto_stream_salsa20_tinynacl(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {
    return salsa_stream_xor(c, 0, l, n, k, 20);
}
