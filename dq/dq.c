/*
 * 20130521
 * Jan Mojzis
 * Public domain.
 */

#include <poll.h>
#include "dns.h"
#include "strtonum.h"
#include "case.h"
#include "die.h"
#include "e.h"
#include "randombytes.h"
#include "byte.h"
#include "stralloc.h"
#include "printpacket.h"
#include "writeall.h"
#include "milliseconds.h"
#include "str.h"
#include "uint16_pack_big.h"
#include "uint16_unpack_big.h"
#include "portparse.h"
#include "base32decode.h"
#include "hexdecode.h"
#include "strtoip.h"
#include "keyparse.h"
#include "typeparse.h"
#include "purge.h"
#include "crypto.h"

#define USAGE "\
\n\
dq: usage:\n\
\n\
 name:\n\
   dq - DNS/DNSCurve query tool\n\
\n\
 synopsis:\n\
   dq [options] type fqdn [host]\n\
   dq -a [options] type fqdn host\n\
\n\
 options:\n\
   -v (optional): print extra information\n\
   -r (optional): send recursive query (default)\n\
   -a (optional): send authoritative query\n\
   -u (optional): use UDP (default)\n\
   -t (optional): use TCP\n\
   -s (optional): send DNSCurve query in streamlined format (default), ignored for regular DNS queries\n\
   -S suffix (optional): send DNSCurve query in TXT format using suffix suffix, ignored for regular DNS queries\n\
   -T timeout (optional): give up on the DNS/DNSCurve query attempt after timeout seconds <1-60> (default 60)\n\
   -p port (optional): send query to port port (default 53)\n\
   -k key (optional): send DNSCurve query and use servers public-key key\n\
   type: DNS query type (A, NS, MX, ANY, PTR, TXT, SOA, SRV, AAAA, AXFR, CNAME or numeric type)\n\
   fqdn: fully qualified domain name\n\
   host: DNS server, hostname or IP address\n\
   \n\
 environment:\n\
   DNSCACHEIP: use IP address $DNSCACHEIP instead of 'nameserver' lines from /etc/resolv.conf\n\
   LOCALDOMAIN: use space separated names from $LOCALDOMAIN instead of 'search' line from /etc/resolv.conf\n\
   DNSREWRITEFILE: use $DNSREWRITEFILE file instead of /etc/dnsrewrite\n\
   \n\
 notes:\n\
   dq rewrites IP address to *.in-addr.arpa or *.ip6.arpa for PTR queries e.g.:\n\
     127.0.0.1 -> 1.0.0.127.in-addr.arpa\n\
     ::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\n\
   \n\
 recursive examples:\n\
   dq any dnscurve.cz\n\
   dq any dnscurve.cz 8.8.8.8\n\
   env DNSCACHEIP=8.8.8.8 dq any dnscurve.cz\n\
   dq ptr 1.0.0.127.in-addr.arpa\n\
   dq ptr 127.0.0.1\n\
   dq ptr ::1\n\
   dq ptr 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\n\
   \n\
 authoritative examples:\n\
   dq -a any dnscurve.cz uz5mj60yr9tnudkkpcglw1y0w6dlh78j1l4gk4z7t8bsf1u4d48wlq.ns.dnscurve.cz\n\
   dq -a -S cz any dnscurve.cz uz5mj60yr9tnudkkpcglw1y0w6dlh78j1l4gk4z7t8bsf1u4d48wlq.ns.dnscurve.cz\n\
   dq -a -k uz5mj60yr9tnudkkpcglw1y0w6dlh78j1l4gk4z7t8bsf1u4d48wlq any dnscurve.cz 2a02:2b88:2:1::127d:1\n\
\n\
"

#define FATAL "dq: fatal: "
#define DEBUG "dq: debug: "

static int flagverbose = 1;
static int flagrecursive = 1;
static int flagtcp = 0;

#define NUMIP 16

static struct global {
    int x;

    unsigned char servers[16 * NUMIP];
    unsigned char keys[33 * NUMIP];

    unsigned char pk[32];
    unsigned char sk[32];

    stralloc out;

    unsigned char qtype[2];
    unsigned char q[256];

    struct dns_transmit tx;
    struct dns_data r;

} g = {0};

static unsigned char *suffix = 0;
static const char *transport = "regular DNS";

static const char *portstr = "53";
static unsigned char port[2];
static char *keystr = 0;
static const char *timeoutstr = "60";
static long long maxtimeout;


static void die_usage(const char *s) {

    if (s) die_4(100, USAGE, FATAL, s, "\n");
    die_1(100, USAGE);
}

static void die_fatal(const char *trouble, const char *fn) {

    purge(&g, sizeof g);

    if (errno) {
        if (fn) die_7(111, FATAL, trouble, " ", fn, ": ", e_str(errno), "\n");
        die_5(111, FATAL, trouble, ": ", e_str(errno), "\n");
    }
    if (fn) die_5(111, FATAL, trouble, " ", fn, "\n");
    die_3(111, FATAL, trouble, "\n");
}


static int resolve(void) {

    long long deadline, stamp, timeout, max;
    struct pollfd x[1];
    int r;

    if (dns_transmit_startext(&g.tx, g.servers, flagrecursive, flagtcp, 0, g.q, g.qtype, 0, port, g.keys, g.pk, suffix) == -1) return -1;

    max = maxtimeout * 1000 + milliseconds();

    for (;;) {
        stamp = milliseconds();
        if (stamp > max) {
            errno = ETIMEDOUT;
            dns_verbosity_queryfailed(&g.tx, flagtcp);
            return -1;
        }
        deadline = max;
        dns_transmit_io(&g.tx, x, &deadline);
        timeout = deadline - stamp;
        if (timeout <= 0) timeout = 20;
        poll(x, 1, timeout);
        r = dns_transmit_get(&g.tx, x, stamp);
        if (r == -1) return -1;
        if (r == 1) break;
    }
    return 0;
}

static int nameparse(unsigned char *s, const char *x) {

    unsigned char ip[16];

    if (!x) return 0;
    if (byte_isequal(g.qtype, 2, DNS_T_PTR)) {
        if (strtoip(ip, x)) x = dns_iptoname(0, ip);
    }
    return dns_domain_fromdot_static(s, (unsigned char *)x, str_len(x));
}

static int ipget(const char *host) {

    if (host) {
        if (dns_ip_qualify(&g.r, host) == -1) return 0;
        if (g.r.result.len == 0) return 0;
        if (g.r.result.len > sizeof g.servers) g.r.result.len = sizeof g.servers;
        byte_copy(g.servers, g.r.result.len, g.r.result.s);
        if (g.r.dnscurvekey && !g.keys[0]) {
            byte_copy(g.keys + 1, 32, g.r.dnscurvekey);
            g.keys[0] = 1;
        }
    }
    else {
        if (!flagrecursive) return 0;
        if (dns_resolvconfip(g.servers) == -1) return 0;
    }
    return 1;

}

static void oops(void) {
    die_fatal("unable to parse", 0);
}

int main(int argc, char **argv) {

    crypto_uint16 u16;
    char *x;
    long long i;

    if (!argv[0]) die_usage(0);
    for (;;) {
        if (!argv[1]) break;
        if (argv[1][0] != '-') break;
        x = *++argv;
        if (x[0] == '-' && x[1] == 0) break;
        if (x[0] == '-' && x[1] == '-' && x[2] == 0) break;
        while (*++x) {
            if (*x == 'q') { flagverbose = 0; continue; }
            if (*x == 'Q') { flagverbose = 1; continue; }
            if (*x == 'v') { if (flagverbose >= 2) flagverbose = 3; else flagverbose = 2; continue; }
            if (*x == 'a') { flagrecursive = 0; continue; }
            if (*x == 'r') { flagrecursive = 1; continue; }
            if (*x == 't') { flagtcp = 1; continue; }
            if (*x == 'u') { flagtcp = 0; continue; }
            if (*x == 's') { dns_domain_free(&suffix); continue; }

            if (*x == 'S') {
                if (x[1]) { dns_domain_fromdot(&suffix, (unsigned char *)x + 1, str_len(x + 1)); break; }
                if (argv[1]) { ++argv; dns_domain_fromdot(&suffix, (unsigned char *)*argv, str_len(*argv)); break; }
            }
            if (*x == 'p') {
                if (x[1]) { portstr = x + 1; break; }
                if (argv[1]) { portstr = *++argv; break; }
            }
            if (*x == 'k') {
                if (x[1]) { keystr = x + 1; ; break; }
                if (argv[1]) { keystr = *++argv; break; }
            }
            if (*x == 'T') {
                if (x[1]) { timeoutstr = x + 1; break; }
                if (argv[1]) { timeoutstr = *++argv; break; }
            }
            die_usage(0);
        }
    }
    if (!strtonum(&maxtimeout, timeoutstr) || maxtimeout < 1 || maxtimeout > 60) die_usage("unable to parse timeout, timeout must be an integer between 1 and 60");
    dns_verbosity_setflag(flagverbose);
    dns_verbosity_setmessage(DEBUG);
    if (!portparse(port, portstr)) die_usage("unable to parse port");
    if (keystr) {
        if (!keyparse(g.keys + 1, 32, keystr)) die_usage("unable to parse key");
        g.keys[0] = 1;
    }
    if (!typeparse(g.qtype, *++argv)) die_usage("unable to parse type");
    if (!nameparse(g.q, *++argv)) die_usage("unable to parse fqdn/IP");
    if (!*++argv) {
         if (!flagrecursive) die_usage("missing host");
         byte_zero(g.keys, sizeof g.keys);
    }
    if (!ipget(*argv)) die_usage("unable to figure out IP from host");

    if (g.keys[0] > 0) {
        crypto_box_curve25519xsalsa20poly1305_keypair(g.pk, g.sk);
        crypto_box_curve25519xsalsa20poly1305_beforenm(g.keys + 1, g.keys + 1, g.sk);
        for (i = 0; i + 33 < sizeof g.keys; ++i) g.keys[i + 33] = g.keys[i]; 
        if (suffix) {
            for (i = 0; i < NUMIP; ++i) g.keys[33 * i] = 2; 
            transport = "txt DNSCurve";
        }
        else {
            transport = "streamlined DNSCurve";
        }
    }

    if (!stralloc_copys(&g.out, "")) oops();
    u16 = uint16_unpack_big(g.qtype);
    if (!stralloc_catnum(&g.out, u16)) oops();
    if (!stralloc_cats(&g.out, " ")) oops();
    if (!dns_domain_todot_cat(&g.out, g.q)) oops();
    if (!stralloc_cats(&g.out, " - ")) oops();
    if (!stralloc_cats(&g.out, transport)) oops();
    if (!stralloc_cats(&g.out, ":\n")) oops();

    if (byte_isequal(g.qtype, 2, DNS_T_AXFR)) {
        if (!stralloc_cats(&g.out, "axfr not supported, use axfr-get\n")) oops();
    }
    else if (resolve() == -1) {
        if (!stralloc_cats(&g.out, e_str(errno))) oops();
        if (!stralloc_cats(&g.out, "\n")) oops();
    }
    else {
        if (g.tx.packetlen < 4) oops();
        if (flagrecursive) {
            g.tx.packet[2] &= ~1;
            g.tx.packet[3] &= ~128;
        }
        if (!printpacket_cat(&g.out, g.tx.packet, g.tx.packetlen)) oops();
    }

    if (writeall(1, g.out.s, g.out.len) == -1) die_fatal("unable to write output", 0);

    purge(&g, sizeof g);
    die_0(0);
    return 111;
}
