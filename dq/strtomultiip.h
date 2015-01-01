#ifndef _STRTOMULTIIP_H____
#define _STRTOMULTIIP_H____

#define STRTOMULTIIP_BUFSIZE 800

extern long long strtomultiip(unsigned char *, long long, const char *);
extern long long strtomultiip4(unsigned char *, long long, const char *);
extern long long strtomultiip6(unsigned char *, long long, const char *);

#endif
