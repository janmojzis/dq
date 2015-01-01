#ifndef _STRALLOC_H____
#define _STRALLOC_H____

typedef struct stralloc {
    unsigned char *s;
    long long len;
    long long alloc;
} stralloc;

extern int stralloc_readyplus(stralloc *, long long);
extern int stralloc_catb(stralloc *, const void *, long long);
extern int stralloc_cats(stralloc *, const void *);
extern int stralloc_cat(stralloc *, stralloc *);
extern int stralloc_copyb(stralloc *, const void *, long long);
extern int stralloc_copys(stralloc *, const void *);
extern int stralloc_copy(stralloc *, stralloc *);
extern int stralloc_append(stralloc *, const void *);
extern int stralloc_0(stralloc *);
extern void stralloc_free(stralloc *);
extern int stralloc_catnum(stralloc *, long long);
extern int stralloc_catnum0(stralloc *, long long, long long);

#endif
