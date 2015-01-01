/*
20130505
Jan Mojzis
Public domain.
*/

#include "env.h"

static char *findkey(const char *y, const char *x) {

    while(*x && *y) if (*y++ != *x++) return (char *)0;
    if (!*x && *y == '=') return (char *)(y + 1);
    return (char *)0;
}

char *env_get(const char *s) {

    char *r;
    long long i;

    if (!s) return (char *)0;
    for (i = 0; environ[i]; ++i) {
        r = findkey(environ[i], s);
        if (r) return r;
    }
    return (char *)0;
}
