#ifndef RESPONSE_H
#define RESPONSE_H

#include "crypto_uint32.h"

extern unsigned char response[];
extern long long response_len;

extern int response_query(const unsigned char *, const unsigned char *, const unsigned char *);
extern void response_nxdomain(void);
extern void response_servfail(void);
extern void response_id(const unsigned char *);
extern void response_tc(void);

extern int response_addbytes(const unsigned char *, long long);
extern int response_addname(const unsigned char *);
extern void response_hidettl(void);
extern int response_rstart(const unsigned char *, const unsigned char *, crypto_uint32);
extern void response_rfinish(int);

#define RESPONSE_ANSWER 6
#define RESPONSE_AUTHORITY 8
#define RESPONSE_ADDITIONAL 10

extern int response_cname(const unsigned char *, const unsigned char *, crypto_uint32);

#endif
