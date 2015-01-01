#include "case.h"

int case_diffb(const void *yv, long long ylen, const void *xv) {

    unsigned char a, b;
    const unsigned char *y = yv;
    const unsigned char *x = xv;

    while (ylen > 0) {
        a = *x++ - 'A'; b = *y++ - 'A'; --ylen;
        if (a <= 'Z' - 'A') a += 'a'; else a += 'A';
        if (b <= 'Z' - 'A') b += 'a'; else b += 'A';
        if (a != b) return ((int)(unsigned int)b) - ((int)(unsigned int)a);
    }
    return 0;
}

int case_diffs(const void *yv, const void *xv) {

    unsigned char a, b;
    const unsigned char *y = yv;
    const unsigned char *x = xv;

    for (;;) {
        a = *x++ - 'A'; b = *y++ - 'A';
        if (a <= 'Z' - 'A') a += 'a'; else a += 'A';
        if (b <= 'Z' - 'A') b += 'a'; else b += 'A';
        if (a != b) break;
        if (!a) break;
    }
    return ((int)(unsigned int)b) - ((int)(unsigned int)a);
}

void case_lowerb(void *xv, long long len) {

    unsigned char *x = xv;
    unsigned char y;

    while (len > 0) {
        --len;
        y = *x - 'A';
        if (y <= 'Z' - 'A') *x = y + 'a';
        ++x;
    }
}

