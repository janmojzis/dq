#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include "env.h"
#include "byte.h"
#include "xsocket.h"
#include "strtoip.h"
#include "randombytes.h"
#include "crypto_uint64.h"
#include "query.h"
#include "die.h"
#include "warn.h"
#include "e.h"
#include "numtostr.h"
#include "strtonum.h"
#include "cache.h"
#include "response.h"
#include "log.h"
#include "roots.h"
#include "hexparse.h"
#include "alloc.h"
#include "milliseconds.h"
#include "blocking.h"
#include "uint16_pack_big.h"
#include "uint16_unpack_big.h"
#include "portparse.h"
#include "droproot.h"
#include "okclient.h"
#include "purge.h"

static int flagokclient = 0;

static int packetquery(unsigned char *buf, long long len, unsigned char **q, unsigned char qtype[2], unsigned char qclass[2], unsigned char id[2]) {

    long long pos;
    unsigned char header[12];

    errno = EPROTO;
    pos = dns_packet_copy(buf, len, 0, header, 12); if (!pos) return 0;
    if (header[2] & 128) return 0; /* must not respond to responses */
    if (!(header[2] & 1)) return 0; /* do not respond to non-recursive queries */
    if (header[2] & 120) return 0;
    if (header[2] & 2) return 0;
    if (!byte_isequal(header + 4, 2, "\0\1")) return 0;

    pos = dns_packet_getname(buf, len, pos, q); if (!pos) return 0;
    pos = dns_packet_copy(buf, len, pos, qtype, 2); if (!pos) return 0;
    pos = dns_packet_copy(buf, len, pos, qclass, 2); if (!pos) return 0;
    if (!byte_isequal(qclass, 2, DNS_C_IN) && !byte_isequal(qclass, 2, DNS_C_ANY)) return 0;

    byte_copy(id, 2, header);
    return 1;
}

static unsigned char myport[2] = {0, 53};
static unsigned char myipoutgoing[32];
static unsigned char myipincoming[16];
static int mytypeincoming = XSOCKET_V6;

static unsigned char buf[1024];
crypto_uint64 numqueries = 0;


static int udp53;

#define MAXUDPDUPLICATED 10
#define MAXUDP 200
static struct udpclient {
    struct query q;
    long long start;
    crypto_uint64 active; /* query number, if active; otherwise 0 */
    struct pollfd *io;
    unsigned char ip[16];
    unsigned char port[2];
    long long scope_id;
    unsigned char id[2];
} u[MAXUDP];
long long uactive = 0;

static void u_drop(long long j) {
    if (!u[j].active) return;
    log_querydrop(&u[j].active);
    u[j].active = 0; --uactive;
}

static void u_respond(long long j) {

    if (!u[j].active) return;
    response_id(u[j].id);
    if (response_len > 512) response_tc();
    xsocket_send(udp53, mytypeincoming, response, response_len, u[j].ip, u[j].port, u[j].scope_id);
    log_querydone(&u[j].active, response_len);
    u[j].active = 0; --uactive;
}


static long long u_duplicatequerycount(unsigned char *q, unsigned char *qtype) {

    long long j, c = 0;
    struct query *z;

    for (j = 0; j < MAXUDP; ++j) {
        if (!u[j].active) continue;
        z = &u[j].q;
        if (!byte_isequal(z->type, 2, qtype)) continue;
        if (!dns_domain_equal(z->name[0], q)) continue;
        ++c;
    }
    return c;
}

static void u_new(void) {

    long long j;
    long long i;
    struct udpclient *x;
    long long len;
    static unsigned char *q = 0;
    unsigned char qtype[2];
    unsigned char qclass[2];
    crypto_uint16 port;

    for (j = 0; j < MAXUDP; ++j)
        if (!u[j].active)
            break;

    if (j >= MAXUDP) {
        j = 0;
        for (i = 1;i < MAXUDP;++i)
            if (u[i].start < u[j].start)
                j = i;
        errno = ETIMEDOUT;
        u_drop(j);
    }

    x = u + j;
    x->start = milliseconds();

    len = xsocket_recv(udp53, mytypeincoming, buf, sizeof buf, x->ip, x->port, &x->scope_id);
    if (len == -1) return;
    if (len >= sizeof buf) return;
    port = uint16_unpack_big(x->port);
    if (port < 1024) if (port != 53) return;

    if (!flagokclient && !okclient(x->ip)) { log_queryreject(x->ip, x->port, 0, 0, 0, "IP address not allowed"); return; }

    if (!packetquery(buf, len, &q, qtype, qclass, x->id)) { log_queryreject(x->ip, x->port, x->id, q, qtype, "bad query"); return; }
    if (u_duplicatequerycount(q, qtype) >= MAXUDPDUPLICATED) { log_queryreject(x->ip, x->port, x->id, q, qtype, "too many duplicate queries"); return; }

    x->active = ++numqueries; ++uactive;
    log_query(&x->active, x->ip, x->port, x->id, q, qtype);
    switch(query_start(&x->q, q, qtype, qclass, myipoutgoing)) {
        case -1:
            u_drop(j);
            return;
        case 1:
            u_respond(j);
    }
}


static int tcp53;

#define MAXTCP 20
struct tcpclient {
    struct query q;
    long long start;
    long long timeout;
    crypto_uint64 active; /* query number or 1, if active; otherwise 0 */
    struct pollfd *io;
    unsigned char ip[16]; /* send response to this address */
    unsigned char port[2]; /* send response to this port */
    long long scope_id;
    int type;
    unsigned char id[2];
    int tcp; /* open TCP socket, if active */
    int state;
    unsigned char *buf; /* 0, or dynamically allocated of length len */
    long long len;
    long long pos;
} t[MAXTCP];
long long tactive = 0;

/*
state 1: buf 0; normal state at beginning of TCP connection
state 2: buf 0; have read 1 byte of query packet length into len
state 3: buf allocated; have read pos bytes of buf
state 0: buf 0; handling query in q
state -1: buf allocated; have written pos bytes
*/

static void t_free(long long j) {
    if (!t[j].buf) return;
    alloc_free(t[j].buf);
    t[j].buf = 0;
}

static void t_timeout(long long j) {

    if (!t[j].active) return;
    t[j].timeout = milliseconds() + 10000;
}

static void t_close(long long j) {
    if (!t[j].active) return;
    t_free(j);
    log_tcpclose(t[j].ip, t[j].port);
    close(t[j].tcp);
    t[j].active = 0; --tactive;
}

static void t_drop(long long j) {
    log_querydrop(&t[j].active);
    errno = EPIPE;
    t_close(j);
}

static void t_respond(long long j) {
    if (!t[j].active) return;
    log_querydone(&t[j].active, response_len);
    response_id(t[j].id);
    t[j].len = response_len + 2;
    t_free(j);
    t[j].buf = alloc(response_len + 2);
    if (!t[j].buf) { t_close(j); return; }
    uint16_pack_big(t[j].buf, response_len);
    byte_copy(t[j].buf + 2, response_len, response);
    t[j].pos = 0;
    t[j].state = -1;
}

static void t_rw(long long j) {

    struct tcpclient *x;
    unsigned char ch;
    static unsigned char *q = 0;
    unsigned char qtype[2];
    unsigned char qclass[2];
    long long r;

    x = t + j;
    if (x->state == -1) {
        r = write(x->tcp, x->buf + x->pos, x->len - x->pos);
        if (r <= 0) { t_close(j); return; }
        x->pos += r;
        if (x->pos == x->len) {
            t_free(j);
            x->state = 1; /* could drop connection immediately */
        }   
        return;
    }

    if (x->state == 1) {
        r = read(x->tcp, &ch, 1);
        if (r == 0) { errno = EPIPE; t_close(j); return; }
        if (r < 0) { t_close(j); return; }
        x->len = (unsigned char) ch;
        x->len <<= 8;
        x->state = 2;
        return;
    }
    if (x->state == 2) {
        r = read(x->tcp, &ch, 1);
        if (r == 0) { errno = EPIPE; t_close(j); return; }
        if (r < 0) { t_close(j); return; }
        x->len += (unsigned char) ch;
        if (!x->len) { errno = EPROTO; t_close(j); return; }
        x->buf = alloc(x->len);
        if (!x->buf) { t_close(j); return; }
        x->pos = 0;
        x->state = 3;
        return;
    }

    if (x->state != 3) return; /* impossible */

    r = read(x->tcp, x->buf + x->pos, x->len - x->pos);
    if (r == 0) { errno = EPIPE; t_close(j); return; }
    if (r < 0) { t_close(j); return; }
    x->pos += r;
    if (x->pos < x->len) return;

    if (!packetquery(x->buf, x->len, &q, qtype, qclass, x->id)) { log_queryreject(x->ip, x->port, x->id, q, qtype, "bad query"); t_close(j); return; }

    x->active = ++numqueries;
    log_query(&x->active, x->ip, x->port, x->id, q, qtype);
    switch(query_start(&x->q,q,qtype,qclass,myipoutgoing)) {
        case -1:
            t_drop(j);
            return;
        case 1:
            t_respond(j);
            return;
    }
    t_free(j);
    x->state = 0;
}

static void t_new(void) {

    long long i;
    long long j;
    struct tcpclient *x;
    crypto_uint16 port;

    for (j = 0;j < MAXTCP;++j)
        if (!t[j].active)
            break;

    if (j >= MAXTCP) {
        j = 0;
        for (i = 1;i < MAXTCP;++i)
            if (t[i].start < t[j].start)
                j = i;
        errno = ETIMEDOUT;
        if (t[j].state == 0)
            t_drop(j);
        else
            t_close(j);
    }

    x = t + j;
    x->start = milliseconds();

    x->tcp = xsocket_accept(tcp53, mytypeincoming, x->ip, x->port, &x->scope_id);
    if (x->tcp == -1) return;
    port = uint16_unpack_big(x->port);
    if (port < 1024) if (port != 53) { close(x->tcp); return; }
    if (!flagokclient && !okclient(x->ip)) { log_queryreject(x->ip, x->port, 0, 0, 0, "IP address not allowed"); close(x->tcp); return; }
    blocking_disable(x->tcp);

    x->active = 1; ++tactive;
    x->state = 1;
    t_timeout(j);

    log_tcpopen(x->ip,x->port);
}

static struct pollfd io[3 + MAXUDP + MAXTCP];
static struct pollfd *udp53io;
static struct pollfd *tcp53io;

static void doit(void) {

    long long j;
    long long deadline;
    long long stamp;
    long long timeout;
    long long iolen;
    int r;

  for (;;) {
    stamp = milliseconds();
    deadline = stamp + 120000;

    iolen = 0;

    udp53io = io + iolen++;
    udp53io->fd = udp53;
    udp53io->events = POLLIN;

    tcp53io = io + iolen++;
    tcp53io->fd = tcp53;
    tcp53io->events = POLLIN;

    for (j = 0;j < MAXUDP;++j)
      if (u[j].active) {
        u[j].io = io + iolen++;
        query_io(&u[j].q,u[j].io,&deadline);
      }
    for (j = 0;j < MAXTCP;++j)
      if (t[j].active) {
        t[j].io = io + iolen++;
        if (t[j].state == 0)
          query_io(&t[j].q,t[j].io,&deadline);
        else {
          if (t[j].timeout < deadline) deadline = t[j].timeout;
          t[j].io->fd = t[j].tcp;
          t[j].io->events = (t[j].state > 0) ? POLLIN : POLLOUT;
        }
      }

      timeout = deadline - stamp;
      if (timeout < 0) timeout = 10;
      poll(io, iolen, timeout);

    for (j = 0;j < MAXUDP;++j)
      if (u[j].active) {
        r = query_get(&u[j].q,u[j].io,stamp);
        if (r == -1) u_drop(j);
        if (r == 1) u_respond(j);
      }

    for (j = 0;j < MAXTCP;++j)
      if (t[j].active) {
        if (t[j].io->revents)
          t_timeout(j);
        if (t[j].state == 0) {
          r = query_get(&t[j].q,t[j].io,stamp);
          if (r == -1) t_drop(j);
          if (r == 1) t_respond(j);
        }
        else
          if (t[j].io->revents || (t[j].timeout < stamp))
            t_rw(j);
      }

    if (udp53io)
      if (udp53io->revents)
        u_new();

    if (tcp53io)
      if (tcp53io->revents)
        t_new();
  }
}


static unsigned char skseed[32];
static unsigned char sk[32 + 16];

#define FATAL "dqcache: fatal: "
#define WARNING "dqcache: warning: "


static void removesecrets(void) {

    query_purge();
    dns_nonce_purge();
    purge(skseed, sizeof skseed);
    purge(sk, sizeof sk);
}

static void die_fatal(const char *trouble, const char *fn) {

    removesecrets();
    if (errno) {
        if (fn) die_7(111, FATAL, trouble, " ", fn, ": ", e_str(errno), "\n");
        die_5(111, FATAL, trouble, ": ", e_str(errno), "\n");
    }
    if (fn) die_5(111, FATAL, trouble, " ", fn, "\n");
    die_3(111, FATAL, trouble, "\n");
}


static char *dnscurvetype = 0;

static void reload(int sig) {
    if (!roots_init(dnscurvetype)) die_fatal("unable to read servers", 0);
}
static void dump(int sig){
    if (cache_dump() == -1) warn_4(WARNING, "unable to dump cache: ", e_str(errno), "\n");
}

static void exitasap(int sig){
    removesecrets();
    dump(0);
    die_0(0);
}

static void clean(int sig){
    cache_clean();
}


int main(int argc, char **argv) {

    long long cachesize, ll;
    unsigned char port[2];
    char *x;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  reload);
    signal(SIGALRM, dump);
    signal(SIGINT, clean);
    signal(SIGTERM, exitasap); 

    if (!strtoip(myipincoming, env_get("IP"))) {
        byte_copy(myipincoming, 16, xsocket_ANYIP);
    }
    mytypeincoming = xsocket_type(myipincoming);

    udp53 = xsocket_udp(mytypeincoming);
    if (udp53 == -1) die_fatal("unable to create UDP socket", 0);
    if (xsocket_bind_reuse(udp53, mytypeincoming, myipincoming, myport, 0) == -1) die_fatal("unable to bind UDP socket", 0);

    tcp53 = xsocket_tcp(mytypeincoming);
    if (tcp53 == -1) die_fatal("unable to create TCP socket", 0);
    if (xsocket_bind_reuse(tcp53, mytypeincoming, myipincoming, myport, 0) == -1) die_fatal("unable to bind TCP socket", 0);

    randombytes(skseed, sizeof skseed);
    x = env_get("SECRETKEY");
    if (x) {
        if (!hexparse(skseed, sizeof skseed, x)) {
            warn_2(WARNING, "unable to parse $SECRETKEY\n");
            randombytes(skseed, sizeof skseed);
        }
        while (*x) { *x = 0; ++x; }
    }

    droproot(FATAL);

    dns_keys_derive(sk, sizeof sk, skseed);
    query_init(sk);

    x = env_get("NONCESTART");
    if (!dns_nonce_init(x, sk + 32)) die_fatal("too long $NONCESTART", x);

    purge(skseed, sizeof skseed);
    purge(sk, sizeof sk);

    dns_transmit_magic(env_get("QUERYMAGIC"), env_get("RESPONSEMAGIC"));

    xsocket_tryreservein(udp53, 131072);

    if (!strtoip(myipoutgoing, env_get("IPSEND4"))) {
        byte_copy(myipoutgoing, 16, xsocket_ANYIP4);
    }
    if (!strtoip(myipoutgoing, env_get("IPSEND6"))) {
        byte_copy(myipoutgoing + 16, 16, xsocket_ANYIP6);
    }
    if (portparse(port, env_get("REMOTEPORT"))) {
        query_remoteport(port);
    }

    if (!strtonum(&cachesize, env_get("CACHESIZE"))) {
        cachesize = 10000000;
    }
    if (!cache_init(cachesize)) die_fatal("not enough memory for cache of size", numtostr(0, cachesize));

    if (env_get("HIDETTL")) response_hidettl();
    if (env_get("FORWARDONLY")) query_forwardonly();
    if (env_get("TCPONLY")) query_tcponly();
    if (env_get("DISABLEIPV6")) query_ipv4only();
    if (strtonum(&ll, env_get("MINTTL"))) query_minttl(ll);
    if (env_get("OKCLIENT")) flagokclient = 1;

    dnscurvetype = env_get("DNSCURVETYPE");
    query_dnscurvetype(dnscurvetype);
    if (!roots_init(dnscurvetype)) die_fatal("unable to read servers", 0);

    if (xsocket_listen(tcp53, 20) == -1) die_fatal("unable to listen on TCP socket", 0);

    if (cache_load() == -1) warn_4(WARNING, "unable to load cache: ", e_str(errno), "\n");

    log_startup();
    doit();

    return 111;
}
