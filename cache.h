#ifndef _CACHE_H____
#define _CACHE_H____

extern int cache_init(long long);
extern void cache_set(const unsigned char *, long long, const unsigned char *, long long, long long, unsigned char);
extern unsigned char *cache_get(const unsigned char *, long long, long long *, long long *, unsigned char *);

extern void cache_clean(void);
extern int cache_dump(void);
extern int cache_load(void);

#endif
