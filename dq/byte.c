/*
20130505
Jan Mojzis
Public domain.
*/

#include "byte.h"

void byte_copy(void *yv, long long ylen, const void *xv) {
    
    long long i;
    const char *x = xv;
    char *y = yv;

    for (i = 0; i < ylen; ++i) y[i] = x[i];
}

void byte_copyr(void *yv, long long ylen, const void *xv) {
    
    long long i;
    const char *x = xv;
    char *y = yv;

    for (i = ylen - 1; i >= 0; --i) y[i] = x[i];
}


long long byte_chr(const void *yv, long long ylen, int c) {

    long long i;
    const char *y = yv;
    char ch = c;

    if (ylen <= 0) return ylen;

    for (i = 0; i < ylen; ++i) if (y[i] == ch) break;
    return i;
}

long long byte_rchr(const void *yv, long long ylen, int c) {

    long long i, u = -1;
    const char *y = yv;
    char ch = c;

    if (ylen <= 0) return ylen;

    for (i = ylen - 1; i >= 0; --i) if (y[i] == ch) { u = i; break; }
    if (u == -1) return ylen;
    return u;
}

void byte_zero(void *yv, long long ylen) {

    long long i;
    char *y = yv;

    for (i = 0; i < ylen; ++i) y[i] = 0;
}

int byte_isequal(const void *yv, long long ylen, const void *xv) {

    long long i;
    const unsigned char *y = yv;
    const unsigned char *x = xv;
    unsigned char diff = 0;

    for (i = 0; i < ylen; ++i) diff |= x[i] ^ y[i];
    return (256 - (unsigned int) diff) >> 8;
}

int byte_diff(const void *yv, long long ylen, const void *xv) {

    long long i;
    const unsigned char *y = yv;
    const unsigned char *x = xv;

    for (i = 0; i < ylen; ++i) {
        if (x[i] == y[i]) continue;
        return ((int)(unsigned int)y[i]) - ((int)(unsigned int)x[i]);
    }
    return 0;
    
}
