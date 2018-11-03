/*
20120421
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include "die.h"
#include "e.h"
#include "env.h"
#include "buffer.h"
#include "dns.h"
#include "byte.h"
#include "str.h"
#include "strtonum.h"
#include "fsyncfd.h"

#define FATAL "dqzonefilter: fatal: "
#define REJECT "#dqzonefilter: line rejected: "


static void die_usage(void) {
    die_1(100, "dqzonefilter: usage: dqzonefilter zone <input >output\n");
}

static void die_fatal(const char *trouble, const char *d, const char *fn) {

    if (d) {
        if (fn) die_9(111,FATAL,trouble," ",d,"/",fn,": ",e_str(errno),"\n");
        die_7(111,FATAL,trouble," ",d,": ",e_str(errno),"\n");
    }
    die_5(111,FATAL,trouble,": ",e_str(errno),"\n");
}

static long long getrev4(char *o, char *buf) {

    char x[4][3]; long long xlen[4] = {0,0,0,0};

    long long i,j = 0;
    long long l = 0;
    long long len;

    len = str_len(buf);

    for (i = 0; i < len; ++i) {
        if (j == 4) break;
        if (buf[i] <= '9' && buf[i] >= '0') {
            if (xlen[j] == 3) return -1;
            x[j][xlen[j]++] = buf[i];
            continue;
        }
        if (buf[i] == '.') {++j; continue;}
        break;
    }
    for(i = 3; i >= 0; --i) {
        for(j = 0; j < xlen[i]; ++j) {
            o[l++] = x[i][j];
        }
        o[l++] = '.';
    }
    byte_copy(o + l, 12, "in-addr.arpa");
    l += 12;
    o[l] = 0;
    return l;
}

#define MAXLINE 1024
static char line[MAXLINE + 1];
static long long linelen = 0;
static int flagin = 1;

#define NUMFIELDS 20
static char *field[NUMFIELDS + 1];
static char fieldbuf[MAXLINE + 1];
static char cmd;

static void out(const char *buf, long long len) {
     if (buffer_put(buffer_1, buf, len) == -1) die_fatal("unable to write output", 0, 0);
}

static void outs(const char *buf) {
    if (!buf) return;
    if (buffer_puts(buffer_1, buf) == -1) die_fatal("unable to write output", 0, 0);
}

static void outrejectline(void) {
    outs(REJECT); outs(line); outs("\n");
}

static int getln(void) {

    char ch = 0;
    long long r;

    linelen = 0;

    while(flagin) {
        if (linelen == MAXLINE) {
            /* line too long */
            outs(REJECT);
            out(line, linelen);
            linelen = 0;
            for(;;) {
                r = buffer_GETC(buffer_0, &ch);
                if (r == -1) die_fatal("unable to read output", 0, 0);
                if (r == 0) {flagin = 0; return 0; }
                if (ch == '\n') ch = 0;
                out(&ch, 1);
                if (!ch) break;
            }
        }

        r = buffer_GETC(buffer_0, &ch);
        if (r == -1) die_fatal("unable to read output", 0, 0);
        if (r == 0) {flagin = 0; break; }
        if (ch == '\n') ch = 0;
        line[linelen++] = ch;
        if (!ch) break;
    }
    r = linelen;

    while(linelen > 0) {
        ch = line[linelen - 1];
        if ((ch != ' ') && (ch != '\t') && (ch != '\n') && (ch != '\r')) break;
        --linelen;
    }
    line[linelen] = 0;
    return (r > 0);
}

static void parseln(void) {

    long long i, j = 0;
    char *p;

    if (linelen <= 0) return;
    cmd = line[0];

    for(i = 0; i < NUMFIELDS; ++i) field[i] = 0;

    p = fieldbuf;
    for(i = 1; i < linelen; ++i) {
        fieldbuf[i-1] = line[i];
        if (p) {
            if (j < NUMFIELDS) field[j++] = p;
            p = 0;
        }
        if (line[i] == ':') {
            fieldbuf[i-1] = 0;
            p = fieldbuf + i;
        }
    }
    fieldbuf[i-1] = 0;
    field[j] = 0;
    return;
}

static char *zone = 0;
static unsigned char qzone[256];
static unsigned char q[256];

static int allowedname(char *name) {

    if (!name) return 0;

    if (!dns_domain_fromdot_static(q, (unsigned char *)name, str_len(name))) {
        if (errno != EPROTO) die_fatal("unable to parse zone", name, 0);
        return 0;
    }

    return dns_domain_suffix(q, qzone);
}

static char *fakettl = 0;
static char *removeloc = 0;

static void doit(void) {

    long long r;
    char bufrev4[29];

    if (!dns_domain_fromdot_static(qzone, (unsigned char *)zone, str_len(zone))) die_fatal("unable to parse zone", zone, 0);

    flagin = 1;
    for (;;) {
        r = getln();
        if (r == 0) break;

        if (!line[0] || line[0] == '#' || line[0] == '-') {
            outs(line); outs("\n");
            continue;
        }

        if (line[0] == '%') {
            if (removeloc) outs(REJECT);
            outs(line); outs("\n");
            continue;
        }

        parseln();

        switch(cmd) {

            case '@':
                /* @fqdn:ip:x:dist:ttl:timestamp:lo */
                if (!allowedname(field[0])) { outrejectline(); break; }
                out(&cmd,1); outs(field[0]);
                outs(":"); outs(field[1]);
                outs(":"); outs(field[2]);
                outs(":"); outs(field[3]);
                outs(":"); if (!fakettl) outs(field[4]); else outs(fakettl);
                outs(":"); outs(field[5]);
                outs(":"); if (!removeloc) outs(field[6]);
                outs("\n");
                break;

            case '\'':
            case '^':
            case 'C':
                /* 'fqdn:s:ttl:timestamp:lo */
                /* ^fqdn:p:ttl:timestamp:lo */
                /* Cfqdn:p:ttl:timestamp:lo */
                if (!allowedname(field[0])) { outrejectline(); break; }
                out(&cmd,1); outs(field[0]);
                outs(":"); outs(field[1]);
                outs(":"); if (!fakettl) outs(field[2]); else outs(fakettl);
                outs(":"); outs(field[3]);
                outs(":"); if (!removeloc) outs(field[4]); 
                outs("\n");
                break;

            case '.':
            case '&':
                /* .fqdn:ip:x:ttl:timestamp:lo */
                /* &fqdn:ip:x:ttl:timestamp:lo */
                if (!allowedname(field[0])) { outrejectline(); break; }
                out(&cmd,1); outs(field[0]);
                outs(":"); outs(field[1]);
                outs(":"); outs(field[2]);
                outs(":"); if (!fakettl) outs(field[3]); else outs(fakettl);
                outs(":"); outs(field[4]);
                outs(":"); if (!removeloc) outs(field[5]); 
                outs("\n");
                break;

            case 'Z':
                /* Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:timestamp:lo */
                if (!allowedname(field[0])) { outrejectline(); break; }
                out(&cmd,1); outs(field[0]);
                outs(":"); outs(field[1]);
                outs(":"); outs(field[2]);
                outs(":"); outs(field[3]);
                outs(":"); outs(field[4]);
                outs(":"); outs(field[5]);
                outs(":"); outs(field[6]);
                outs(":"); outs(field[7]);
                outs(":"); if (!fakettl) outs(field[8]); else outs(fakettl);
                outs(":"); outs(field[9]);
                outs(":"); if (!removeloc) outs(field[10]); 
                outs("\n");
                break;

            case '=':
                /* =fqdn:ip:ttl:timestamp:lo */
                if (getrev4(bufrev4, field[1]) > 0) {
                    if (allowedname(bufrev4)) {
                        /* ^fqdn:p:ttl:timestamp:lo */
                        outs("^"); outs(bufrev4);
                        outs(":"); outs(field[0]);
                        outs(":"); if (!fakettl) outs(field[2]); else outs(fakettl);
                        outs(":"); outs(field[3]);
                        outs(":"); if (!removeloc) outs(field[4]);
                        outs("\n");
                    }
                }

            case '+':
                /* +fqdn:ip:ttl:timestamp:lo */
                if (!allowedname(field[0])) { outrejectline(); break; }
                outs("+"); outs(field[0]);
                outs(":"); outs(field[1]);
                outs(":"); if (!fakettl) outs(field[2]); else outs(fakettl);
                outs(":"); outs(field[3]);
                outs(":"); if (!removeloc) outs(field[4]);
                outs("\n");
                break;

            case ':':
                /* :fqdn:n:rdata:ttl:timestamp:lo */
                if (!allowedname(field[0])) { outrejectline(); break; }
                if (!strtonum(&r, field[1])) { outrejectline(); break; }
                if (r == 0)   { outrejectline(); break; } /* no 0 */
                if (r == 252) { outrejectline(); break; } /* no AXFR */
                if (r == 6)   { outrejectline(); break; } /* no SOA */
                if (r == 2)   { outrejectline(); break; } /* no NS */
                if (r == 5)   { outrejectline(); break; } /* no CNAME */
                if (r == 12)  { outrejectline(); break; } /* no PTR */
                if (r == 15)  { outrejectline(); break; } /* no MX */
                outs(":"); outs(field[0]);
                outs(":"); outs(field[1]);
                outs(":"); outs(field[2]);
                outs(":"); if (!fakettl) outs(field[3]); else outs(fakettl);
                outs(":"); outs(field[4]);
                outs(":"); if (!removeloc) outs(field[5]);
                outs("\n");
                break;

            default:
                outrejectline();
                break;
        }
    }
    return;
}


int main(int argc, char **argv) {

    if (!argv[0]) die_usage();
    if (!argv[1]) die_usage();
    zone = argv[1];

    fakettl = env_get("FAKETTL");
    removeloc = env_get("REMOVELOC");

    doit();

    if (buffer_flush(buffer_1) == -1) die_fatal("unable to write output", 0, 0);
    if (fsyncfd(1) == -1) die_fatal("unable to write output", 0, 0);
    if (close(1) == -1) die_fatal("unable to write output", 0, 0);
    _exit(0);
}

