#include "crypto.h"
#include "dns.h"  

static const unsigned char zero[16] = {0};
static const unsigned char sigma[16] = "expand 32-byte k";

void dns_keys_derive(unsigned char *out, unsigned char *skseed) {

    crypto_core_salsa20(out, zero, skseed, sigma);
}
