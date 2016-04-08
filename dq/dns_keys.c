#include "crypto.h"
#include "dns.h"  

static const unsigned char zero[8] = {0};

void dns_keys_derive(unsigned char *out, long long outlen, unsigned char *skseed) {

    crypto_stream_salsa20(out, outlen, zero, skseed);
}
