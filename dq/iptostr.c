/*
20130604
Jan Mojzis
Public domain.
*/

#include "byte.h"
#include "iptostr.h"

static char *iptostr4(char *strbuf, const unsigned char *ip) {

    long long i;
    unsigned long long num;

    strbuf += IPTOSTR_LEN - 1;
    *strbuf = 0;

    for (i = 3; i >= 0; --i) {
        num = ip[i];
        do {
            *--strbuf = '0' + (num % 10);
            num /= 10;
        } while (num);
        if (i > 0) *--strbuf = '.';
    }
    return strbuf;
}

static void minmax(long long *min, long long *max, const unsigned long long *ip) {

    long long i, j, e;
    long long count[8];


    for (i = 7; i >= 0; --i) count[i] = 0;

    e = 8;
    for (i = 7; i >= 0; --i) {
        if (!ip[i]) {
            for (j = i; j < e; ++j) ++count[j];
        }
        else {
            e = i;
        }
    }

    e = 0; j = 0;
    for (i = 7; i >= 0; --i) {
        if (count[i]) {
            if (count[i] >= e) { e = count[i]; j = i; }
        }
    }

    *min = j - count[j] + 1;
    *max = j;
}

static char *iptostr6(char *strbuf, const unsigned char *ip) {

    long long i;
    long long min, max;
    unsigned long long ip2[8];

    for (i = 7; i >= 0; --i) {
        ip2[i] = ip[2 * i];
        ip2[i] <<= 8;
        ip2[i] += ip[2 * i + 1];
    }

    minmax(&min, &max, ip2);

    strbuf += IPTOSTR_LEN - 1;
    *strbuf = 0;

    for (i = 7; i >= 0; --i) {

        if (i <= max && i >= min && min != max) {
            if (i == max) *--strbuf = ':';
            if (i == 7) *--strbuf = ':';
            continue;
        }

        do {
            *--strbuf = "0123456789abcdef"[ip2[i] & 15];
            ip2[i] >>= 4;
        } while (ip2[i]);
        if (i > 0) *--strbuf = ':';
    }
    return strbuf;
}

char *iptostr(char *strbuf, const unsigned char *ip) {

    static char staticbuf[IPTOSTR_LEN];

    if (!strbuf) strbuf = staticbuf; /* not thread-safe */

    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) {
        return iptostr4(strbuf, ip + 12);
    }
    return iptostr6(strbuf, ip);
}
