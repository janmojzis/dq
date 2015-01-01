/*
20130505
Jan Mojzis
Public domain.
*/

#include "str.h"

long long str_len(const char *s) {

    long long i;

    for (i = 0; s[i]; ++i);
    return i;
}


long long str_chr(const char *s, int c) {

    long long i;
    char ch = c;

    for (i = 0; s[i]; ++i) if (s[i] == ch) break;
    return i;
}

long long str_rchr(const char *s, int c) {

    long long i, u = -1;
    char ch = c;

    for (i = 0; s[i]; ++i) if (s[i] == ch) u = i;
    if (u != -1) return u;
    return i;
}

int str_diff(const char *s, const char *t) {

    register char x;

    for (;;) {
        x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
        x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
        x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
        x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
    }
    return ((int)(unsigned int)(unsigned char) x)
        - ((int)(unsigned int)(unsigned char) *t);
}

int str_start(const char *s, const char *t) {

    char x;

    for (;;) {
        x = *t++; if (!x) return 1; if (x != *s++) return 0;
        x = *t++; if (!x) return 1; if (x != *s++) return 0;
        x = *t++; if (!x) return 1; if (x != *s++) return 0;
        x = *t++; if (!x) return 1; if (x != *s++) return 0;
    }
}

