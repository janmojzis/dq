#ifndef _ALLOC_H____
#define _ALLOC_H____

#ifdef TEST
extern void alloc_setlimit(long long);
extern long long alloc_getallocated(void);
extern long long alloc_getspace(void);
#endif

extern void *alloc(long long);
extern void alloc_free(void *x);
extern int alloc_re(void **x, long long, long long);
extern void alloc_freeall(void);

#endif

