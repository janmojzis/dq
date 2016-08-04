#include "buffer.h"
#include "uint32_unpack_big.h"
#include "uint16_unpack_big.h"
#include "e.h"
#include "byte.h"
#include "iptostr.h"
#include "numtostr.h"
#include "log.h"

/* work around gcc 2.95.2 bug */
#define number(x) ( (u64 = (x)), u64_print() )
static crypto_uint64 u64;
static void u64_print(void) {
    char buf[20];
    long long pos;

    pos = sizeof buf;
    do {
        if (pos <= 0) break;
        buf[--pos] = '0' + (u64 % 10);
        u64 /= 10;
    } while(u64);

    buffer_put(buffer_2, buf + pos, sizeof buf - pos);
}

static void hex(unsigned char c) {
    buffer_put(buffer_2, "0123456789abcdef" + (c >> 4), 1);
    buffer_put(buffer_2, "0123456789abcdef" + (c & 15), 1);
}

static void string(const char *s) {
    buffer_puts(buffer_2, s);
}

static void line(void) {
    string("\n");
    buffer_flush(buffer_2);
}

static void space(void) {
    string(" ");
}

static void ip(const unsigned char i[16]) {
#if 1
    string(iptostr(0, i));
#else
    hex(i[0]); hex(i[1]); hex(i[2]); hex(i[3]);
    hex(i[4]); hex(i[5]); hex(i[6]); hex(i[7]);
    hex(i[8]); hex(i[9]); hex(i[10]); hex(i[11]);
    hex(i[12]); hex(i[13]); hex(i[14]); hex(i[15]);
#endif
}

static void dctype(unsigned char x) {

    switch(x) {
        case 1: string("S"); break;
        case 2: string("T"); break;
        default: string("R"); break;
    }
}

static void logid(const unsigned char id[2]) {
#if 1
    string(numtostr(0, uint16_unpack_big(id)));
#else
    hex(id[0]);
    hex(id[1]);
#endif
}

static void logtype(const unsigned char type[2]) {

    crypto_uint16 u;

    u = uint16_unpack_big(type);
    number(u);
}

static void name(const unsigned char *q) {

    unsigned char ch;
    int state;

    if (!*q) {
        string(".");
        return;
    }

    while(state = *q++) {
        while (state) {
            ch = *q++;
            --state;
            if ((ch <= 32) || (ch > 126)) ch = '?';
            if ((ch >= 'A') && (ch <= 'Z')) ch += 32;
            buffer_put(buffer_2, (char *)&ch, 1);
        }
        string(".");
    }
}

void log_startup(void) {
    string("starting");
    line();
}

void log_dnscurvekey(const unsigned char *key) {

    long long i;
    string("dnscurve public-key ");
    for(i = 0; i < 32; ++i) {
        hex(key[i]);
    }
    line();
}

void log_query(crypto_uint64 *qnum, const unsigned char client[16], unsigned char port[2], const unsigned char id[2], const unsigned char *q, const unsigned char qtype[2]) {

    string("query "); number(*qnum); space();
    ip(client); string(":"); string(numtostr(0, uint16_unpack_big(port)));
    string(":"); logid(id); space();
    logtype(qtype); space(); name(q);
    line();
}


void log_queryreject(const unsigned char *client, unsigned char *port, const unsigned char *id, const unsigned char *q, const unsigned char *qtype, const char *x) {

    string("reject ");
    ip(client); string(":"); string(numtostr(0, uint16_unpack_big(port)));
    string(":");

    if (id) {
        logid(id);
    }
    else {
        string("?");
    }
    space();

    if (qtype) {
        logtype(qtype);
    }
    else {
        string("?");
    }
    space();

    if (q) {
        name(q);
    }
    else {
        string("?");
    }
    space();
    string(x);
    line();
}

void log_querydone(crypto_uint64 *qnum, long long len) {
    string("sent "); number(*qnum); space();
    number(len);
    line();
}

void log_querydrop(crypto_uint64 *qnum) {

    const char *x = e_str(errno);

    string("drop "); number(*qnum); space();
    string(x);
    line();
}

void log_tcpopen(const unsigned char client[16], unsigned char port[2]) {
    string("tcpopen ");
    ip(client); string(":"); hex(port[0]); hex(port[1]);
    line();
}

void log_tcpclose(const unsigned char client[16],unsigned char port[2]) {

    const char *x = e_str(errno);
    string("tcpclose ");
    ip(client); string(":"); hex(port[0]); hex(port[1]); space();
    string(x);
    line();
}

/* XXX */
void log_tx(const unsigned char *q, const unsigned char qtype[2], const unsigned char *control, const unsigned char servers[256], const unsigned char keys[528], int flaghavekeys, unsigned int gluelessness) {

    long long i, j;
    const unsigned char *k;

    string("tx "); number(gluelessness); space();
    logtype(qtype); space(); name(q); space();
    name(control);
    string(flaghavekeys ? " +" : " -");
    for (i = 0; i < 256; i += 16) {
        j = i >> 4;
        if (!byte_isequal(servers + i, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
            k = keys + 33 * j;
            space();
            dctype(k[0]);
            ip(servers + i);
        }
    }
    line();
}

void log_cachedanswer(const unsigned char *q,const unsigned char type[2])
{
  string("cached "); logtype(type); space();
  name(q);
  line();
}

void log_cachedcname(const unsigned char *dn,const unsigned char *dn2)
{
  string("cached cname "); name(dn); space(); name(dn2);
  line();
}

void log_cachedns(const unsigned char *control,const unsigned char *ns)
{
  string("cached ns "); name(control); space(); name(ns);
  line();
}

void log_cachednxdomain(const unsigned char *dn)
{
  string("cached nxdomain "); name(dn);
  line();
}

void log_nxdomain(const unsigned char *server,const unsigned char *q,unsigned int ttl)
{
  string("nxdomain "); ip(server); space(); number(ttl); space();
  name(q);
  line();
}

void log_nodata(const unsigned char *server,const unsigned char *q,const unsigned char qtype[2],unsigned int ttl)
{
  string("nodata "); ip(server); space(); number(ttl); space();
  logtype(qtype); space(); name(q);
  line();
}

void log_lame(const unsigned char *server,const unsigned char *control,const unsigned char *referral)
{
  string("lame "); ip(server); space();
  name(control); space(); name(referral);
  line();
}

void log_ignore_referral(const unsigned char *server, const unsigned char *control, const unsigned char *referral)
{
  string("ignored referral "); ip(server); space();
  name(control); space(); name(referral);
  line();
}

void log_servfail(const unsigned char *dn)
{
  const char *x = e_str(errno);

  string("servfail "); name(dn); space();
  string(x);
  line();
}

void log_cachedservfail(const unsigned char *dn, const unsigned char *dt)
{
  string("cached servfail "); name(dn); space();
  logtype(dt);
  line();
}

void log_rr(const unsigned char *server,const unsigned char *q,const unsigned char type[2],const unsigned char *buf,unsigned int len,unsigned int ttl, unsigned char flagkey)
{
  int i;

  string("rr "); dctype(flagkey); ip(server); space(); number(ttl); space();
  logtype(type); space(); name(q); space();

  for (i = 0;i < len;++i) {
    hex(buf[i]);
    if (i > 30) {
      string("...");
      break;
    }
  }
  line();
}

void log_rra(const unsigned char *server,const unsigned char *q,const unsigned char *data,unsigned int ttl, unsigned char flagkey)
{
  unsigned char i[16];
  byte_copy(i, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
  byte_copy(i + 12, 4, data);
  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" a "); name(q); space();
  string(iptostr(0, i));
  line();
}

void log_rraaaa(const unsigned char *server,const unsigned char *q,const unsigned char *data,unsigned int ttl, unsigned char flagkey)
{
  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" aaaa "); name(q); space();
  string(iptostr(0, data));
  line();
}

void log_rrns(const unsigned char *server,const unsigned char *q,const unsigned char *data,unsigned int ttl, unsigned char flagkey)
{
  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" ns "); name(q); space();
  name(data);
  line();
}

void log_rrcname(const unsigned char *server,const unsigned char *q,const unsigned char *data,unsigned int ttl, unsigned char flagkey)
{
  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" cname "); name(q); space();
  name(data);
  line();
}

void log_rrptr(const unsigned char *server,const unsigned char *q,const unsigned char *data,unsigned int ttl, unsigned char flagkey)
{
  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" ptr "); name(q); space();
  name(data);
  line();
}

void log_rrmx(const unsigned char *server,const unsigned char *q,const unsigned char *mx,const unsigned char pref[2],unsigned int ttl, unsigned char flagkey)
{
  crypto_uint16 u;

  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" mx "); name(q); space();
  u = uint16_unpack_big(pref);
  number(u); space(); name(mx);
  line();
}

void log_rrsoa(const unsigned char *server,const unsigned char *q,const unsigned char *n1,const unsigned char *n2,const unsigned char misc[20],unsigned int ttl,unsigned char flagkey)
{
  crypto_uint32 u;
  int i;

  string("rr "); dctype(flagkey); ip(server); space(); number(ttl);
  string(" soa "); name(q); space();
  name(n1); space(); name(n2);
  for (i = 0;i < 20;i += 4) {
    u = uint32_unpack_big(misc + i);
    space(); number(u);
  }
  line();
}


void log_stats(void)
{
  extern crypto_uint64 numqueries;
  extern crypto_uint64 cache_motion;
  extern crypto_uint64 cache_hit;
  extern crypto_uint64 cache_miss;
  extern crypto_uint64 tx4;
  extern crypto_uint64 tx6;
  extern int uactive;
  extern int tactive;

  string("stats ");
  number(numqueries); space();
  number(cache_motion); space();
  number(uactive); space();
  number(tactive); space();
  number(cache_hit); space();
  number(cache_miss); space();
  number(tx4); space();
  number(tx6);
  line();
}
