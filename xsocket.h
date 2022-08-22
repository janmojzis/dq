#ifndef _XSOCKET_H____
#define _XSOCKET_H____

#include "hasipv6.h"

#define XSOCKET_V4 4
#define XSOCKET_V6 6

extern int xsocket_tcp(int);
extern int xsocket_udp(int);

extern long long xsocket_send(int, int, const unsigned char *, long long, const unsigned char *, const unsigned char *, long long);
extern long long xsocket_recv(int, int, unsigned char *, long long, unsigned char *, unsigned char *, long long *);

extern int xsocket_bind(int, int, const unsigned char *, const unsigned char *, long long);
extern int xsocket_bind_reuse(int, int, const unsigned char *, const unsigned char *, long long);
extern void xsocket_tryreservein(int, int);
extern int xsocket_listen(int, long long);
extern int xsocket_accept(int, int, unsigned char *, unsigned char *, long long *);
extern int xsocket_local(int, int, unsigned char *, unsigned char *, long long *);

extern int xsocket_connect(int, int, const unsigned char *, const unsigned char *, long long);
extern int xsocket_connected(int);

extern int xsocket_ipoptionskill(int);
extern int xsocket_tcpnodelay(int);
extern long long xsocket_getscopeid(const char *);

extern int xsocket_type(const unsigned char *);

#define xsocket_ANYIP6 (const unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define xsocket_ANYIP4 (const unsigned char *)"\0\0\0\0\0\0\0\0\0\0\377\377\0\0\0\0"
#define xsocket_PREFIX4 (const unsigned char *)"\0\0\0\0\0\0\0\0\0\0\377\377"

#ifdef HASIPV6
  #define xsocket_ANYIP xsocket_ANYIP6
#else
  #define xsocket_ANYIP xsocket_ANYIP4
#endif

#endif
