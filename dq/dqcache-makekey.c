/*
20160325
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include "randombytes.h"
#include "writeall.h"

static unsigned char sk[32];
static unsigned char out[65];

int main(int argc, char **argv) {

    long long i;

    randombytes(sk, sizeof sk);
    for (i = 0; i < 32; ++i) {
        out[2 * i + 0] = "0123456789abcdef"[15 & (int) (sk[i] >> 4)]; 
        out[2 * i + 1] = "0123456789abcdef"[15 & (int) (sk[i] >> 0)];
    }
    out[2 * i] = '\n';
    if (writeall(1, out, sizeof out) == -1) _exit(111);
    fsync(1);
    _exit(0);
}
