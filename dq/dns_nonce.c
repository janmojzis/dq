/*
version 20130522
Jan Mojzis
Public domain.
*/

#include "nanoseconds.h"
#include "randombytes.h"
#include "uint32_pack.h"
#include "uint32_unpack.h"
#include "crypto_uint64.h"
#include "byte.h"
#include "purge.h"
#include "dns.h"

#define NSS 1 /* nonce separation space, 1 - 3 bytes */

static unsigned char noncekey[16] = {0};
static crypto_uint64 noncecounter = 0;
static unsigned char noncemask[NSS];
static unsigned char noncedata[NSS];

void dns_nonce_purge(void) {
    purge(noncekey, sizeof noncekey);
}

int dns_nonce_init(const char *ns, const unsigned char *nk) {

    long long i;

    noncecounter = nanoseconds();

    for (i = 0; i < NSS; ++i) noncemask[i] = 0xff;
    for (i = 0; i < NSS; ++i) noncedata[i] = 0x00;

    if (!ns) ns = "";
    i = 0;
    while (i < 8 * NSS) {
        if (ns[i] != '0' && ns[i] != '1') break;
        noncemask[i/8] = noncemask[i/8] * 2;
        noncedata[i/8] = noncedata[i/8] * 2 + ns[i] - '0';
        ++i;
    }

    if (ns[i] == '0' || ns[i] == '1') return 0;

    while (i < 8 * NSS) {
        noncemask[i/8] = noncemask[i/8] * 2 + 1;
        noncedata[i/8] = noncedata[i/8] * 2;
        ++i;
    }

    if (nk) byte_copy(noncekey, sizeof noncekey, nk);
    else randombytes(noncekey, sizeof noncekey);
    return 1;
}

static void dns_nonce_encrypt(unsigned char *out, crypto_uint64 in, const unsigned char *k) {

    long long i;

    crypto_uint32 v0, v1, k0, k1, k2, k3;
    crypto_uint32 sum = 0;
    crypto_uint32 delta = 0x9e3779b9;

    v0 = in; in >>= 32;
    v1 = in;
    k0 = uint32_unpack(k + 0);
    k1 = uint32_unpack(k + 4);
    k2 = uint32_unpack(k + 8);
    k3 = uint32_unpack(k + 12);

    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    } 
    uint32_pack(out + 0, v0);
    uint32_pack(out + 4, v1);
}

/*
n is 12-byte nonce with the following structure:
n[0...NSS-1]: random or nonce-separation bits
n[NSS...4]: random
n[4...11]: TEA encrypted counter
*/

void dns_nonce(unsigned char *n) {

    long long x;

    if (!noncecounter) dns_nonce_init(0, 0);

    x = nanoseconds();
    if (x > noncecounter) noncecounter = x;

    randombytes(n, 4);
    for(x = 0; x < NSS; ++x) {
        n[x] &= noncemask[x];
        n[x] += noncedata[x];
    }

    dns_nonce_encrypt((n + 4), ++noncecounter, noncekey); 
}
