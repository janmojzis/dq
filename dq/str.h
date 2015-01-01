#ifndef _STR_H____
#define _STR_H____

extern long long str_len(const char *);
extern long long str_chr(const char *, int);
extern long long str_rchr(const char *, int);
extern int str_diff(const char *, const char *);
extern int str_start(const char *, const char *);
#define str_equal(s,t) (!str_diff((s),(t)))

#endif
