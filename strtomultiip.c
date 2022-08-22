/*
20130607
Jan Mojzis
Public domain.
*/

#include "byte.h"
#include "str.h"
#include "strtoip.h"
#include "strtomultiip.h"

static char separators[] = { ',', ' ', '\t', '\n', 0 };

static long long _strtomultiip(unsigned char *ip, long long ipmax, const char *x, int (*op)(unsigned char *, const char *)) {

    unsigned char data[STRTOMULTIIP_BUFSIZE];

    long long i, j, k;
    long long iplen = 0;
    long long len;

    if (!x) return 0;

    byte_zero(ip, ipmax);

    len = str_len(x);
    if (len > STRTOMULTIIP_BUFSIZE - 1) {
        len = STRTOMULTIIP_BUFSIZE - 1;
        for (j = 0; separators[j]; ++j) len = byte_rchr(x, len, separators[j]);
    }
    byte_copy(data, len, x);
    data[len++] = 0;

    /* separators ',' ' ' '\t' '\n' */
    for (i = 0; i < len; ++i) {
        for (j = 0; separators[j]; ++j) if (data[i] == separators[j]) data[i] = 0;
    }

    /* separator '.' - IPv4 backward compatibility */
    j = byte_chr(data, len, ':');
    if (j == len) {
        k = 0;
        for (i = 0; i < len; ++i) {
            if (data[i] == 0) k = 0;
            if (data[i] == '.') if (++k % 4 == 0) data[i] = 0;
        }
    }

    /* parse ip */
    i = 0;
    for (j = 0; j < len; ++j) {
        if (data[j] == 0) {
            if (iplen + 16 <= ipmax) {
                if (op(ip + iplen, (char *)data + i)) {
                    iplen += 16;
                }
            }
            i = j + 1;
        }
    }

    return iplen;
}

long long strtomultiip4(unsigned char *ip, long long ipmax, const char *x) {
    return _strtomultiip(ip, ipmax, x, strtoip4);
}

long long strtomultiip6(unsigned char *ip, long long ipmax, const char *x) {
    return _strtomultiip(ip, ipmax, x, strtoip6);
}

long long strtomultiip(unsigned char *ip, long long ipmax, const char *x) {
    return _strtomultiip(ip, ipmax, x, strtoip);
}

