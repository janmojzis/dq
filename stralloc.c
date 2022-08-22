/*
20130505
Jan Mojzis
Public domain.
*/

#include "alloc.h"
#include "e.h"
#include "stralloc.h"

int stralloc_readyplus(stralloc *r, long long len) {

    unsigned char *newdata;
    long long i;

    if (!r || len < 0) { errno = EINVAL; return 0; }
    if (len == 0) return 1;

    if (r->len + len + 1 > r->alloc) {
        while (r->len + len + 1 > r->alloc)
            r->alloc = 2 * r->alloc + 1;
        newdata = alloc(r->alloc);
        if (!newdata) return 0;
        if (r->s) {
            for (i = 0; i < r->len; ++i) newdata[i] = r->s[i];
            alloc_free(r->s);
        }
        r->s = newdata;
    }
    return 1;
}

int stralloc_catb(stralloc *r, const void *xv, long long xlen) {

    const unsigned char *x = xv;
    long long i;

    if (!r || !xv || xlen < 0) { errno = EINVAL; return 0; }
    if (xlen == 0) return 1;

    if (!stralloc_readyplus(r, xlen)) return 0;
    for (i = 0; i < xlen; ++i) r->s[r->len + i] = x[i];
    r->len += xlen;
    return 1;
}

int stralloc_cats(stralloc *r, const void *xv) {

    const unsigned char *x = xv;
    long long xlen;

    if (!r || !xv) { errno = EINVAL; return 0; }

    for (xlen = 0; x[xlen]; ++xlen);
    return stralloc_catb(r, x, xlen);
}

int stralloc_cat(stralloc *x, stralloc *y) {

    if (!y) { errno = EINVAL; return 0; }

    return stralloc_catb(x, y->s, y->len);
}

int stralloc_copyb(stralloc *r, const void *xv, long long xlen) {

    if (!r) { errno = EINVAL; return 0; }

    r->len = 0;
    return stralloc_catb(r, xv, xlen);
}

int stralloc_copys(stralloc *r, const void *xv) {

    if (!r) { errno = EINVAL; return 0; }

    r->len = 0;
    return stralloc_cats(r, xv);
}

int stralloc_copy(stralloc *x, stralloc *y) {

    if (!x || !y) { errno = EINVAL; return 0; }

    x->len = 0;
    return stralloc_cat(x, y);
}

int stralloc_append(stralloc *r, const void *xv) {
    return stralloc_catb(r, xv, 1);
}

int stralloc_0(stralloc *r) {
    return stralloc_append(r, "");
}


static int stralloc_catunum0(stralloc *sa, unsigned long long u, long long n) {

    long long len;
    unsigned long long q;
    unsigned char *s;

    if (!sa) { errno = EINVAL; return 0; }

    len = 1;
    q = u;
    while (q > 9) { ++len; q /= 10; }
    if (len < n) len = n;

    if (!stralloc_readyplus(sa, len)) return 0;
    s = sa->s + sa->len;
    sa->len += len;
    while (len) { s[--len] = '0' + (u % 10); u /= 10; }

    return 1;
}

int stralloc_catnum0(stralloc *sa, long long l, long long n) {

    if (!sa) { errno = EINVAL; return 0; }

    if (l < 0) {
        if (!stralloc_append(sa,"-")) return 0;
        l = -l;
    }
    return stralloc_catunum0(sa, l, n);
}

int stralloc_catnum(stralloc *r, long long num) {
    return stralloc_catnum0(r, num, 0);
}

void stralloc_free(stralloc *r) {

    if (!r) return;
    if (r->s) alloc_free(r->s);
    r->s = 0;
    r->len = 0;
    r->alloc = 0;
}
