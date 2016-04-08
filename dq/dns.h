#ifndef _DNS_H____
#define _DNS_H____

#include <poll.h>
#include "stralloc.h"

#define DNS_C_IN (unsigned char *)"\0\1"
#define DNS_C_ANY (unsigned char *)"\0\377"

#define DNS_T_A (unsigned char *)"\0\1"
#define DNS_T_NS (unsigned char *)"\0\2"
#define DNS_T_CNAME (unsigned char *)"\0\5"
#define DNS_T_SOA (unsigned char *)"\0\6"
#define DNS_T_PTR (unsigned char *)"\0\14"
#define DNS_T_MX (unsigned char *)"\0\17"
#define DNS_T_TXT (unsigned char *)"\0\20"
#define DNS_T_AAAA (unsigned char *)"\0\34"
#define DNS_T_SRV (unsigned char *)"\0\41"
#define DNS_T_AXFR (unsigned char *)"\0\374"
#define DNS_T_ANY (unsigned char *)"\0\377"

#define DNS_MAGICQ (unsigned char *)"Q6fnvWj8"
#define DNS_MAGICR (unsigned char *)"R6fnvWJ8"

struct dns_transmit {
    unsigned char *query; /* 0, or dynamically allocated */
    long long querylen;
    unsigned char *packet; /* 0, or dynamically allocated */
    long long packetlen;
    int s1; /* 0, or 1 + an open file descriptor */
    int s1type;
    long long tcpstate;
    long long udploop;
    long long curserver;
    long long deadline;
    long long pos;
    const unsigned char *servers;
    unsigned char localip[32];
    unsigned char qtype[2];
    unsigned char port[2];
    long long scope_id;

    long long paddinglen;
    unsigned char id[2];
    unsigned char nonce[12];
    const unsigned char *keys;
    const unsigned char *pk;
    const unsigned char *suffix;
    const unsigned char *name;
    int flagrecursive;
    int flagipv4only;
};

#define DNS_HASKEY(d) (d->keys && *(d->keys + 33 * d->curserver))
#define DNS_ISTXT(d) (d->keys && (*(d->keys + 33 * d->curserver) == 2))
#define DNS_KEYPTR(d) d->keys + 33 * d->curserver + 1

/* dns_domain */
extern void dns_domain_free(unsigned char **);
extern int dns_domain_copy(unsigned char **, const unsigned char *);
extern long long dns_domain_length(const unsigned char *);
extern int dns_domain_equal(const unsigned char *, const unsigned char *);
extern int dns_domain_suffix(const unsigned char *, const unsigned char *);
extern long long dns_domain_suffixpos(const unsigned char *, const unsigned char *);
extern int dns_domain_fromdot(unsigned char **, const unsigned char *, long long);
extern int dns_domain_fromdot_static(unsigned char *, const unsigned char *, long long);
extern int dns_domain_todot_cat(stralloc *, const unsigned char *);

/* dns_packet */
extern long long dns_packet_copy(const unsigned char *,long long,long long,unsigned char *,long long);
extern long long dns_packet_getname(const unsigned char *,long long,long long,unsigned char **);
extern long long dns_packet_skipname(const unsigned char *,long long,long long);
extern long long dns_packet_getname_static(const unsigned char *,long long,long long,unsigned char *);

/* dns_transmit */
extern int dns_transmit_start(struct dns_transmit *d, const unsigned char servers[256], int flagrecursive, const unsigned char *q, const unsigned char qtype[2], const unsigned char localip[32]);
extern int dns_transmit_startext(struct dns_transmit *d, const unsigned char servers[256], int flagrecursive, int flagtcp, int flagipv4only, const unsigned char *q, const unsigned char qtype[2], const unsigned char localip[32], const unsigned char port[2], const unsigned char keys[528], const unsigned char pk[32], const unsigned char *suffix);

extern void dns_transmit_free(struct dns_transmit *);
extern void dns_transmit_io(struct dns_transmit *,struct pollfd *,long long *);
extern int dns_transmit_get(struct dns_transmit *,const struct pollfd *,const long long);

extern void dns_transmit_magic(const char *, const char *);


/* dns_data */
struct dns_data {

    /* ---- OUTPUT */
    
    /* name */
    unsigned char *name;
    stralloc fqdn;

    /* result */
    stralloc result;

    /* keys */
    unsigned char *curvecpkey;
    unsigned char *dnscurvekey;

    /* ---- INPUT */

    /* options */
    char curvecpselector;
};

extern void dns_data_free(struct dns_data *);

extern int dns_resolvconfip(unsigned char *);
extern int dns_resolve(const unsigned char *q, const unsigned char qtype[2]);
extern struct dns_transmit dns_resolve_tx;
extern int dns_ip(struct dns_data *, const char *);
extern int dns_ip4(struct dns_data *, const char *);
extern int dns_ip6(struct dns_data *, const char *);

extern int dns_resolvconfrewrite(stralloc *);
extern int dns_ip_qualify(struct dns_data *, const char *);
extern int dns_ip4_qualify(struct dns_data *, const char *);
extern int dns_ip6_qualify(struct dns_data *, const char *);

#define DNS_IPTONAME_LEN 73
extern char *dns_iptoname(char *, const unsigned char *);

/* utils */
extern void dns_sortip(unsigned char *, long long);
extern void dns_sortipkey(unsigned char *, unsigned char *, long long);

/*base32 */
extern long long dns_base32_bytessize(long long);
extern void dns_base32_encodebytes(unsigned char *, const unsigned char *, long long);
extern void dns_base32_encodekey(unsigned char *, const unsigned char *);
extern long long base32_decode(unsigned char *, const unsigned char *, long long, int);

/* nonce */
extern void dns_nonce_purge(void);
extern int dns_nonce_init(const char *, const unsigned char *);
extern void dns_nonce(unsigned char *);

/* verbose */
extern int dns_verbosity_flag;
extern const char *dns_verbosity_message;
extern void dns_verbosity_setflag(int);
extern void dns_verbosity_setmessage(const char *);
extern void dns_verbosity_writehex(const char *, const unsigned char *, long long);
extern void dns_verbosity_writedomain(const char *, unsigned char *);
extern void dns_verbosity_resolving(const char *);
extern void dns_verbosity_resolved(struct dns_data *, const char *);
extern void dns_verbosity_querysent(struct dns_transmit *, int);
extern void dns_verbosity_queryfailed(struct dns_transmit *, int);
extern void dns_verbosity_queryfailedtc(struct dns_transmit *);
extern void dns_verbosity_queryok(struct dns_transmit *);

/* keys */
extern void dns_keys_derive(unsigned char *, long long, unsigned char *);

#endif
