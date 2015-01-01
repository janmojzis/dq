#include "fastrandombytes.h"
#include "fastrandommod.h"

/* XXX: current implementation is limited to n<2^55 */

long long fastrandommod(long long n) {

    long long result = 0;
    long long j;
    unsigned char r[64];
    if (n <= 1) return 0;
    fastrandombytes(r, 64);
    for (j = 0; j < 64; ++j) result = (result * 256 + (unsigned long long) r[j]) % n;
    return result;
}
