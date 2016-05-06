/*
20130503
Jan Mojzis
Public domain.
*/

#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "e.h"
#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "byte.h"
#include "purge.h"
#include "alloc.h"

#define ALLOC_ALIGNMENT 16
#define ALLOC_SPACE 8192
#define ALLOC_LIMIT 4000000000LL

typedef union { unsigned char irrelevant[ALLOC_ALIGNMENT]; double d; } aligned;
static aligned realspace[ALLOC_SPACE / ALLOC_ALIGNMENT];
#define space ((unsigned char *) realspace)
static long long avail = ALLOC_SPACE;

static long long allocated = 0;
static long long limit     = -1;

static long long getlimit(void) {

    struct rlimit r;

    if (limit >= 0) return limit;

#ifdef RLIMIT_DATA
    if (getrlimit(RLIMIT_DATA, &r) == 0) {
        if (r.rlim_cur > r.rlim_max)
            r.rlim_cur = r.rlim_max;
        limit = (long long)r.rlim_cur;
    }
#endif
    if (limit < 0 || limit > ALLOC_LIMIT) limit = ALLOC_LIMIT;
    return limit;
}

#ifdef TEST
void alloc_setlimit(long long l) {
    limit = l;
}

long long alloc_getallocated(void) {
    return allocated;
}

long long alloc_getspace(void) {
    return ALLOC_SPACE;
}
#endif

static void **ptr = 0;
static long long ptrlen = 0;
static long long ptralloc = 0;

static int ptr_add(void *x) {

    void **newptr;

    if (ptrlen + 1 > ptralloc) {
        while (ptrlen + 1 > ptralloc)
            ptralloc = 2 * ptralloc + 1;
        newptr = (void **)malloc(ptralloc * sizeof(void *));
        if (!newptr) return 0;
        if (ptr) {
            byte_copy(newptr, ptrlen * sizeof(void *), ptr);
            free(ptr);
        }
        ptr = newptr;
    }
    if (!x) return 1;
    ptr[ptrlen++] = x;
    return 1;
}

static int ptr_remove(void *x) {

    long long i;

    for (i = 0; i < ptrlen; ++i) {
        if (ptr[i] == x) goto ok;
    }
    return 0;
ok:
    --ptrlen;
    ptr[i] = ptr[ptrlen];
    return 1;
}

void *alloc(long long nn) {

    unsigned char *x;
    crypto_uint64 n;

    if (nn < 0 || nn > ALLOC_LIMIT) goto nomem;
    if (nn == 0) nn = 1;
    n = nn;

    n = ALLOC_ALIGNMENT + n - (n & (ALLOC_ALIGNMENT - 1));
    if (n <= avail) { avail -= n; return (void *)(space + avail); }

    n += ALLOC_ALIGNMENT;

    if (allocated + n > getlimit()) goto nomem;

    x = (unsigned char *)malloc(n);
    if (!x) goto nomem;

    allocated += n;
    byte_zero(x, n);
    uint64_pack(x, n);
    x += ALLOC_ALIGNMENT;
    if (!ptr_add(x)) goto nomem;
    return (void *)x;

nomem:
    errno = ENOMEM;
    return (void *)0;
}

void alloc_free(void *xv) {

    crypto_uint64 n;
    unsigned char *x = xv;

    if (x >= space)
        if (x < space + ALLOC_SPACE)
            return;

    if (!ptr_remove(x)) return;
    x -= ALLOC_ALIGNMENT;
    n = uint64_unpack(x);
    allocated -= n;

    purge(x, n);
    free(x);
}

void alloc_freeall(void) {

    while (ptrlen > 0) {
        alloc_free(ptr[0]);
    }
    if (ptr) { free(ptr); ptr = 0; ptrlen = 0; ptralloc = 0; }
    purge(space, ALLOC_SPACE);
}
