#ifndef LOG_H
#define LOG_H

#include "crypto_uint64.h"

extern void log_startup(void);
extern void log_dnscurvekey(const unsigned char *key);

extern void log_query(crypto_uint64 *,const unsigned char *,unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
extern void log_queryreject(const unsigned char *, unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const char *);
extern void log_querydrop(crypto_uint64 *);
extern void log_querydone(crypto_uint64 *,long long);

extern void log_tcpopen(const unsigned char *,unsigned char *);
extern void log_tcpclose(const unsigned char *,unsigned char *);

extern void log_cachedanswer(const unsigned char *,const unsigned char *);
extern void log_cachedcname(const unsigned char *,const unsigned char *);
extern void log_cachednxdomain(const unsigned char *);
extern void log_cachedns(const unsigned char *,const unsigned char *);

extern void log_tx(const unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *,int,unsigned int);

extern void log_nxdomain(const unsigned char *,const unsigned char *,unsigned int);
extern void log_nodata(const unsigned char *,const unsigned char *,const unsigned char *,unsigned int);
extern void log_servfail(const unsigned char *);
extern void log_cachedservfail(const unsigned char *, const unsigned char *);
extern void log_lame(const unsigned char *,const unsigned char *,const unsigned char *);
extern void log_ignore_referral(const unsigned char *,const unsigned char *,const unsigned char *);

extern void log_rr(const unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned int,unsigned char);
extern void log_rra(const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);
extern void log_rraaaa(const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);
extern void log_rrns(const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);
extern void log_rrcname(const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);
extern void log_rrptr(const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);
extern void log_rrmx(const unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);
extern void log_rrsoa(const unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *,unsigned int,unsigned char);

extern void log_stats(void);

#endif
