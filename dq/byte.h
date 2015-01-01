#ifndef _BYTE_H____
#define _BYTE_H____

void byte_copy(void *, long long, const void *);
void byte_copyr(void *, long long, const void *);
long long byte_chr(const void *, long long, int);
long long byte_rchr(const void *, long long, int);
void byte_zero(void *, long long);
int byte_isequal(const void *, long long, const void *);
int byte_diff(const void *, long long, const void *);

#endif
