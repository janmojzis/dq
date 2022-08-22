/*
20130604
Jan Mojzis
Public domain.
*/

#include <arpa/inet.h>
#include <sys/socket.h>
#include "byte.h"
#include "strtoip.h"

/* taken from nacl-20110221, from curvecp/curvecpserver.c (public-domain) */
int strtoip4(unsigned char *ip, const char *x) {

    unsigned char *y = ip + 12;
    long long j;
    long long k;
    long long d;

    if (!x) return 0;
    for (k = 0; k < 4; ++k) y[k] = 0;
    for (k = 0; k < 4; ++k) {
        d = 0;
        for (j = 0; j < 3 && x[j] >= '0' && x[j] <= '9'; ++j) d = d * 10 + (x[j] - '0');
        if (j == 0) return 0;
        x += j;
        if (k >= 0 && k < 4) y[k] = d;
        if (k < 3) {
            if (*x != '.') return 0;
            ++x;
        }
    }
    if (*x) return 0;
    byte_copy(ip, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
    return 1;
}

/* XXX TODO rewrite without inet_pton */
int strtoip6(unsigned char *ip, const char *x) {

    if (!x) return 0;
    if (inet_pton(AF_INET6, x, ip) != 1) return 0;
    return 1;
}

int strtoip(unsigned char *ip, const char *x) {

    if (strtoip4(ip, x)) return 1;
    if (strtoip6(ip, x)) return 1;
    return 0;
}

