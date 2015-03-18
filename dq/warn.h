#ifndef _WARN_H____
#define _WARN_H____

extern void warn_9(const char *,const char *,const char *,const char *,const char *,const char *,const char *,const char *,const char *);

#define warn_8(a,b,c,d,e,f,g,h) warn_9(a,b,c,d,e,f,g,h,0)
#define warn_7(a,b,c,d,e,f,g) warn_8(a,b,c,d,e,f,g,0)
#define warn_6(a,b,c,d,e,f) warn_7(a,b,c,d,e,f,0)
#define warn_5(a,b,c,d,e) warn_6(a,b,c,d,e,0)
#define warn_4(a,b,c,d) warn_5(a,b,c,d,0)
#define warn_3(a,b,c) warn_4(a,b,c,0)
#define warn_2(a,b) warn_3(a,b,0)
#define warn_1(a) warn_2(a,0)

#endif
