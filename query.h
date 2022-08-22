#ifndef QUERY_H
#define QUERY_H

#include "dns.h"
#include "crypto_uint32.h"

#define QUERY_MAXLEVEL 5
#define QUERY_MAXALIAS 16
#define QUERY_MAXNS 16
#define QUERY_MAXLOOP 500

struct query {
  unsigned int loop;
  unsigned int level;
  unsigned char *name[QUERY_MAXLEVEL];
  unsigned char *control[QUERY_MAXLEVEL]; /* pointing inside name */
  unsigned char *ns[QUERY_MAXLEVEL][QUERY_MAXNS];
  unsigned char servers[QUERY_MAXLEVEL][256];
  unsigned char keys[QUERY_MAXLEVEL][528];
  int flaghavekeys[QUERY_MAXLEVEL];
  int ipv6[QUERY_MAXLEVEL];
  unsigned char *alias[QUERY_MAXALIAS];
  crypto_uint32 aliasttl[QUERY_MAXALIAS];
  unsigned char localip[32];
  unsigned char type[2];
  unsigned char class[2];
  struct dns_transmit dt;
} ;

extern int query_start(struct query *,unsigned char *,unsigned char *,unsigned char *,unsigned char *);
extern void query_io(struct query *,struct pollfd *,long long *);
extern int query_get(struct query *,struct pollfd *,long long);

extern void query_init(const unsigned char *);
extern void query_purge(void);
extern void query_forwardonly(void);
extern void query_tcponly(void);
extern void query_ipv4only(void);
extern void query_minttl(long long);
extern void query_remoteport(unsigned char *);
extern void query_dnscurvetype(char *);

#endif
