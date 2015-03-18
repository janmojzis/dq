/*
20140727
Jan Mojzis
Public domain.
*/

#include "crypto_uint64.h"
#include "crypto_uint32.h"
#include "uint32_pack.h"
#include "uint32_unpack.h"
#include "cleanup.h"
#include "salsa.h"

#define ROTATE(x, c) ((x) << (c)) | ((x) >> (32 - (c)))

/* sigma: "expand 32-byte k" */
static const crypto_uint32 sigma[4] = { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 };

void salsa_core(unsigned char *out, crypto_uint32 *n, const crypto_uint32 *k, const crypto_uint32 *c, int h, long long r) {

    long long i, j, m;
    crypto_uint32 x[16], y[16], t[4], w[16];

    for (i = 0; i < 4; ++i) {
        x[i *  5] = c[i    ];
        x[i +  1] = k[i    ];
        x[i +  6] = n[i    ];
        x[i + 11] = k[i + 4];
    }

    for (i = 0; i < 16; ++i) y[i] = x[i];

    for (i = 0; i < r; ++i) {
        for (j = 0; j < 4; ++j) {
            for (m = 0; m < 4; ++m) t[m] = x[(5 * j + 4 * m) % 16];
            t[1] ^= ROTATE(t[0] + t[3],  7);
            t[2] ^= ROTATE(t[1] + t[0],  9);
            t[3] ^= ROTATE(t[2] + t[1], 13);
            t[0] ^= ROTATE(t[3] + t[2], 18);
            for (m = 0; m < 4; ++m) w[4 * j + (j + m) % 4] = t[m];
        }
        for (j = 0; j < 16; ++j) x[j] = w[j];
    }


    if (h) {
        for (i = 0; i < 16; ++i) x[i] += y[i];
        for (i = 0; i < 4; ++i) {
            x[5 * i] -= c[i];
            x[6 + i] -= n[i];
        }
        for (i = 0; i < 4; ++i) {
            uint32_pack(out      + 4 * i, x[5 * i]);
            uint32_pack(out + 16 + 4 * i, x[6 + i]);
        }
    }
    else {
        for (i = 0; i < 16; ++i) uint32_pack(out + 4 * i, x[i] + y[i]);
    }

    cleanup(x); cleanup(y); cleanup(t); cleanup(w);
}

int salsa_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *nn, const unsigned char *kk, long long r) {

    unsigned char x[64];
    crypto_uint32 k[8], n[4];
    long long i;
    crypto_uint64 u;

    if (!l) return 0;

    for (i = 0; i < 8; ++i) k[i    ] = uint32_unpack(kk + 4 * i);
    for (i = 0; i < 2; ++i) n[i + 2] = 0;
    for (i = 0; i < 2; ++i) n[i    ] = uint32_unpack(nn + 4 * i);

    while (l >= 64) {
        salsa_core(m ? x : c, n, k, sigma, 0, r);
        if (m) for (i = 0; i < 64; ++i) c[i] = m[i] ^ x[i];

        u = 1;
        for (i = 0; i < 2; ++i) {
            u += (crypto_uint64)n[i + 2];
            n[i + 2] = u;
            u >>= 32;
        }

        l -= 64;
        c += 64;
        if (m) m += 64;
    }
    if (l) {
        salsa_core(x, n, k, sigma, 0, r);
        for (i = 0; i < l; ++i) c[i] = (m ? m[i] : 0) ^ x[i];
    }
    cleanup(x); cleanup(k); cleanup(n);
    return 0;
}
