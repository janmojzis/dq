/*
- based on crypto_auth/siphash24/little2 from supercop-20140622
*/

#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "siphash.h"

#define ROTATE(x,b) x = (x << b) | (x >> (64 - b))

#define ROUND \
  do { \
  v0 += v1; v2 += v3; \
  ROTATE(v1,13); ROTATE(v3,16); \
  v1 ^= v0; v3 ^= v2; \
  ROTATE(v0,32); \
  v2 += v1; v0 += v3; \
  ROTATE(v1,17); ROTATE(v3,21); \
  v1 ^= v2; v3 ^= v0; \
  ROTATE(v2,32); \
  } while(0);

int siphash(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k, long long rounds, long long finalrounds) {

    crypto_uint64 v0, v1, v2, v3, lastblock = inlen;
    unsigned char block[8];
    long long i;

    v0 = v2 = uint64_unpack(k + 0);
    v1 = v3 = uint64_unpack(k + 8);

    v0 ^= 0x736f6d6570736575;
    v1 ^= 0x646f72616e646f6d;
    v2 ^= 0x6c7967656e657261;
    v3 ^= 0x7465646279746573;

    while (inlen >= 8) {
        crypto_uint64 mi = uint64_unpack(in);
        in += 8;
        v3 ^= mi;
        for (i = 0; i < rounds; ++i) ROUND
        v0 ^= mi;
        inlen -= 8;
    }

    for (i = 0; i < 7;     ++i) block[i] = 0;
    for (i = 0; i < inlen; ++i) block[i] = in[i];
    block[7] = lastblock;
    lastblock = uint64_unpack(block);

    v3 ^= lastblock;
    for (i = 0; i < rounds; ++i) ROUND
    v0 ^= lastblock;

    v2 ^= 0xff;
    for (i = 0; i < finalrounds; ++i) ROUND

    uint64_pack(out, (v0 ^ v1) ^ (v2 ^ v3));
    return 0;
}
