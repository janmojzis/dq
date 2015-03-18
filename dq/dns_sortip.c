#include "randommod.h"
#include "byte.h"
#include "dns.h"

static void swap(unsigned char *x, long long len, unsigned char *y) {

    unsigned char t[33];

    byte_copy(t, len, x);
    byte_copy(x, len, y);
    byte_copy(y, len, t);

}

void dns_sortip(unsigned char *s, long long nn) {

    long long i;
    long long n = nn;

    if (nn < 0) return;

    n >>= 4;
    while (n > 1) {
        i = randommod(n);
        --n;
        swap(s + 16 * i, 16, s + 16 * n);
    }

    for (i = 0; i + 16 <= nn; i += 16) {
        if (!byte_isequal(s + i, 12, "\0\0\0\0\0\0\0\0\0\0\377\377")) {
            swap(s + i, 16, s);
            break;
        }
    }
}

void dns_sortipkey(unsigned char *s, unsigned char *t, long long nn) {

    long long i, j, k;
    long long n;
    unsigned char *key;

    nn >>=4;
    n = nn;

    while (n > 1) {
        i = randommod(n);
        --n;
        swap(s + 16 * i, 16, s + 16 * n);
        swap(t + 33 * i, 33, t + 33 * n);
    }

    n = nn;
    j = 0;
    k = 0;
    for (i = k; i < n; ++i) {
        key = t + 33 * i;
        if (key[0] == 1) {
            swap(s + 16 * i, 16, s + 16 * j);
            swap(t + 33 * i, 33, t + 33 * j);
            ++j;
        }
    }
    for (i = k; i < j; ++i) {
        key = t + 33 * i;
        if (key[0] != 1) continue;
        if (!byte_isequal(s + 16 * i, 12, "\0\0\0\0\0\0\0\0\0\0\377\377")) {
            swap(s + 16 * i, 16, s + 16 * k);
            swap(t + 33 * i, 33, t + 33 * k);
            break;
        }
    }

    k = j;
    for (i = k; i < n; ++i) {
        key = t + 33 * i;
        if (key[0] == 2) {
            swap(s + 16 * i, 16, s + 16 * j);
            swap(t + 33 * i, 33, t + 33 * j);
            ++j;
        }
    }
    for (i = k; i < j; ++i) {
        key = t + 33 * i;
        if (key[0] != 2) continue;
        if (!byte_isequal(s + 16 * i, 12, "\0\0\0\0\0\0\0\0\0\0\377\377")) {
            swap(s + 16 * i, 16, s + 16 * k);
            swap(t + 33 * i, 33, t + 33 * k);
            break;
        }
    }

    k = j;
    for (i = k; i < n; ++i) {
        key = t + 33 * i;
        if (!byte_isequal(s + 16 * i, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
            swap(s + 16 * i, 16, s + 16 * j);
            swap(t + 33 * i, 33, t + 33 * j);
            ++j;
        }
    }
    for (i = k; i < j; ++i) {
        key = t + 33 * i;
        if (key[0] != 0) continue;
        if (!byte_isequal(s + 16 * i, 12, "\0\0\0\0\0\0\0\0\0\0\377\377")) {
            swap(s + 16 * i, 16, s + 16 * k);
            swap(t + 33 * i, 33, t + 33 * k);
            break;
        }
    }
}
