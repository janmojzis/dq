#include "byte.h"
#include "dns.h"

static const char base32_digits[32] = "0123456789bcdfghjklmnpqrstuvwxyz";

long long dns_base32_bytessize(long long len) {

    if (len < 0) return 0;
    len = (8 * len + 4) / 5;
    return len + (len + 49) / 50;
}
    
void dns_base32_encodebytes(unsigned char *out, const unsigned char *in, long long len) {

    unsigned long long i, x, v, vbits;

    if (len < 0) return;

    x = v = vbits = 0;
    for (i = 0; i < len; ++i) {
        v |= ((unsigned long long)in[i]) << vbits;
        vbits += 8;
        do {
            out[++x] = base32_digits[v & 31];
            v >>= 5;
            vbits -= 5;
            if (x == 50) {
                *out = x;
                out += 1 + x;
                x = 0;
            }
        } while (vbits >= 5);
    }

    if (vbits) out[++x] = base32_digits[v & 31];
    if (x) *out = x;
}

void dns_base32_encodekey(unsigned char *out, const unsigned char *key) {

    unsigned long long i, v, vbits;

    byte_copy(out, 4, "\66x1a");
    out += 4;

    v = vbits = 0;
    for (i = 0; i < 32; ++i) {
        v |= ((unsigned long long)key[i]) << vbits;
        vbits += 8;
        do {
            *out++ = base32_digits[v & 31];
            v >>= 5;
            vbits -= 5;
        } while (vbits >= 5);
    }
}

static const unsigned char val[128] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x0a, 0x0b, 0x0c, 0xff, 0x0d, 0x0e,
    0x0f, 0xff, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x0a, 0x0b, 0x0c, 0xff, 0x0d, 0x0e,
    0x0f, 0xff, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff
};



long long base32_decode(unsigned char *out, const unsigned char *in, long long len, int mode) {

    long long i;
    unsigned long long x, v, vbits;
    unsigned char *out0 = out;

    if (len < 0) return 0;

    v = vbits = 0;
    for (i = 0; i < len; ++i) {
        if (in[i] & 0x80) return 0;
        x = val[in[i]];
        if (x > 0x1f) return 0;
        v |= x << vbits;
        vbits += 5;
        if (vbits >= 8) {
            *out++ = v;
            v >>= 8;
            vbits -= 8;
        }
    }

    if (mode) {
        if (vbits)
            *out++ = v;
    }
    else if (vbits >= 5 || v)
        return 0;

    return out - out0;
}
