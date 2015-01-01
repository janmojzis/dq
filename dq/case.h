#ifndef _CASE_H____
#define _CASE_H____

extern int case_diffb(const void *, long long, const void *);
extern int case_diffs(const void *, const void *);
extern void case_lowerb(void *, long long);

#define case_equals(s,t) (!case_diffs((s),(t)))


#endif
