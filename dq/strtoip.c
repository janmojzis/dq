/*
20130604
Jan Mojzis
Public domain.
*/

/* XXX TODO rewrite without inet_pton */

#include "inet_pton.h"
#include "byte.h"
#include "strtoip.h"

int strtoip4(unsigned char *ip, const char *x) {

    if (!x) return 0;

    if (inet_pton4(x, (ip + 12)) != 1) return 0;
    byte_copy(ip, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
    return 1;
}

int strtoip6(unsigned char *ip, const char *x) {

    if (!x) return 0;

    if (inet_pton6(x, ip) != 1) return 0;
    return 1;
}

int strtoip(unsigned char *ip, const char *x) {

    if (strtoip4(ip, x)) return 1;
    if (strtoip6(ip, x)) return 1;
    return 0;
}

