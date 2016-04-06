#include <unistd.h>
#include "alloc.h"
#include "milliseconds.h"
#include "xsocket.h"
#include "e.h"
#include "byte.h"
#include "uint16_pack_big.h"
#include "uint16_unpack_big.h"
#include "randombytes.h"
#include "randommod.h"
#include "case.h"
#include "str.h"
#include "dns.h"
#include "crypto.h"

unsigned char *magicq = DNS_MAGICQ;
unsigned char *magicr = DNS_MAGICR;

void dns_transmit_magic(const char *mq, const char *mr) {
    if (mq && str_len(mq) == 8) magicq = (unsigned char *)mq;
    if (mr && str_len(mr) == 8) magicr = (unsigned char *)mr;
}

static void basequery(struct dns_transmit *d, unsigned char *query) {

    long long len;

    len = dns_domain_length(d->name);

    byte_copy(query, 2, d->id);
    byte_copy(query + 2, 10, d->flagrecursive ? "\1\0\0\1\0\0\0\0\0\0" : "\0\0\0\1\0\0\0\0\0\0gcc-bug-workaround");
    byte_copy(query + 12, len, d->name);
    byte_copy(query + 12 + len, 2, d->qtype);
    byte_copy(query + 14 + len, 2, DNS_C_IN);
    if (d->paddinglen > 0) {
        byte_zero(query + 16 + len, d->paddinglen);
        query[16 + len + d->paddinglen - 1] = 0x80;
    }
}

static void regularquery(struct dns_transmit *d) {

    long long len;

    d->paddinglen = 0;

    len = dns_domain_length(d->name) + d->paddinglen;
    d->querylen = len + 18;

    uint16_pack_big(d->query, d->querylen - 2);
    randombytes(d->id, 2);
    basequery(d, d->query + 2);
    d->name = d->query + 14;
}

static void streamlinedquery(struct dns_transmit *d) {

    long long len;
    unsigned char nonce[24];

    d->paddinglen = (2 + randommod(2)) * 64 - (dns_domain_length(d->name) + 16) % 64;

    len = dns_domain_length(d->name) + d->paddinglen;
    d->querylen = len + 86;

    dns_nonce(d->nonce);
    byte_copy(nonce, 12, d->nonce);
    byte_zero(nonce + 12, 12);
    dns_verbosity_writehex("DNSCurve pk: ", d->pk, 32);
    dns_verbosity_writehex("DNSCurve nonce: ", nonce, 24);

    byte_zero(d->query + 38, 32);
    randombytes(d->id, 2);
    basequery(d, d->query + 38 + 32);
    crypto_box_curve25519xsalsa20poly1305_afternm(d->query + 38, d->query + 38, len + 48, nonce, DNS_KEYPTR(d));

    uint16_pack_big(d->query, d->querylen - 2);
    byte_copy(d->query + 2, 8, magicq);
    byte_copy(d->query + 10, 32, d->pk);
    byte_copy(d->query + 42, 12, nonce);
}

static void txtquery(struct dns_transmit *d) {

    long long len, suffixlen, m;
    unsigned char nonce[24];

    d->paddinglen = 0;

    len = dns_domain_length(d->name) + d->paddinglen;
    suffixlen = dns_domain_length(d->suffix);
    m = dns_base32_bytessize(len + 44);
    d->querylen = m + suffixlen + 73;

    dns_nonce(d->nonce);
    byte_copy(nonce, 12, d->nonce);
    byte_zero(nonce + 12, 12);
    dns_verbosity_writehex("DNSCurve pk: ", d->pk, 32);
    dns_verbosity_writehex("DNSCurve nonce: ", nonce, 24);

    byte_zero(d->query, 32);
    randombytes(d->id, 2);
    basequery(d, d->query + 32);
    crypto_box_curve25519xsalsa20poly1305_afternm(d->query, d->query, len + 48, nonce, DNS_KEYPTR(d));

    byte_copyr(d->query + d->querylen - len - 32, len + 32, d->query + 16);
    byte_copy(d->query + d->querylen - len - 44, 12, nonce);

    uint16_pack_big(d->query, d->querylen - 2);
    randombytes(d->query + 2, 2);
    byte_copy(d->query + 4, 10, "\0\0\0\1\0\0\0\0\0\0");
    dns_base32_encodebytes(d->query + 14,d->query + d->querylen - len - 44, len + 44);
    dns_base32_encodekey(d->query + 14 + m, d->pk);
    byte_copy(d->query + 69 + m, suffixlen, d->suffix);
    dns_verbosity_writedomain("DNSCurve txt: ", d->query + 14);
    byte_copy(d->query + 69 + m + suffixlen, 2, DNS_T_TXT);
    byte_copy(d->query + 69 + m + suffixlen + 2, 2, DNS_C_IN);
}

static void makequery(struct dns_transmit *d) {

    if (!DNS_HASKEY(d)) { regularquery(d); return; }
    if (!DNS_ISTXT(d)) { streamlinedquery(d); return; }
    txtquery(d);
}

static int getquery(const struct dns_transmit *d, unsigned char *buf, long long *lenp) {

    long long len;
    unsigned char nonce[24];
    long long pos;
    unsigned char out[16];
    long long namelen;
    long long txtlen;
    long long i, j;
    unsigned char ch;
    crypto_uint16 datalen;

    if (!DNS_HASKEY(d)) return 0;

    len = *lenp;

    if (!DNS_ISTXT(d)) {
        if (len < 48) return 1;
        if (!byte_isequal(buf, 8, magicr)) return 1;
        if (!byte_isequal(buf + 8, 12, d->nonce)) return 1;
        byte_copy(nonce, 24, buf + 8);
        dns_verbosity_writehex("DNSCurve nonce: ", nonce, 24);
        byte_zero(buf + 16, 16);
        if (crypto_box_curve25519xsalsa20poly1305_open_afternm(buf + 16, buf + 16, len - 16, nonce, DNS_KEYPTR(d))) return 1;
        byte_copy(buf, len - 48, buf + 48);
        *lenp = len - 48;
        return 0;
    }

    pos = dns_packet_copy(buf, len, 0, out, 12); if (!pos) return 1;
    if (!byte_isequal(out, 2, d->query + 2)) return 1; 
    if (!byte_isequal(out + 2, 10, "\204\0\0\1\0\1\0\0\0\0")) return 1;

    /* query name might be >255 bytes, so can't use dns_packet_getname */
    namelen = dns_domain_length(d->query + 14);
    if (namelen > len - pos) return 1;
    if (case_diffb(buf + pos, namelen, d->query + 14)) return 1;
    pos += namelen;

    pos = dns_packet_copy(buf, len, pos, out, 16); if (!pos) return 1;
    if (!byte_isequal(out, 14, "\0\20\0\1\300\14\0\20\0\1\0\0\0\0")) return 1;
    datalen = uint16_unpack_big(out + 14);
    if (datalen > len - pos) return 1;

    j = 4;
    txtlen = 0;
    for (i = 0; i < datalen; ++i) {
        ch = buf[pos + i];
        if (!txtlen)
            txtlen = ch;
        else {
            --txtlen;
            buf[j++] = ch;
        }
    }
    if (txtlen) return 1;

    if (j < 32) return 1;
    byte_copy(nonce, 12, d->nonce);
    byte_copy(nonce + 12, 12, buf + 4);
    dns_verbosity_writehex("DNSCurve nonce: ", nonce, 24);
    byte_zero(buf, 16);
    if (crypto_box_curve25519xsalsa20poly1305_open_afternm(buf, buf, j, nonce, DNS_KEYPTR(d))) return 1;
    byte_copy(buf, j - 32, buf + 32);
    *lenp = j - 32;
    return 0;
}

static int serverwantstcp(const unsigned char *buf, long long len) {

    unsigned char out[12];

    if (!dns_packet_copy(buf, len, 0, out, 12)) return 1;
    if (out[2] & 2) return 1;
    return 0;
}

static int serverfailed(const unsigned char *buf, long long len) {
  
    unsigned char out[12];
    unsigned long long rcode;

    if (!dns_packet_copy(buf, len, 0, out, 12)) return 1;
    rcode = out[3];
    rcode &= 15;
    if (rcode && (rcode != 3)) { errno = EAGAIN; return 1; }
    return 0;
}

static int irrelevant(const struct dns_transmit *d, const unsigned char *buf, long long len) {

    unsigned char out[12];
    unsigned char *dn;
    long long pos;

    pos = dns_packet_copy(buf, len, 0, out, 12); if (!pos) return 1;
    if (!byte_isequal(out, 2, d->id)) return 1;
    if (out[4] != 0) return 1;
    if (out[5] != 1) return 1;

    dn = 0;
    pos = dns_packet_getname(buf, len, pos, &dn); if (!pos) return 1;
    if (!dns_domain_equal(dn, d->name)) { alloc_free(dn); return 1; }
    alloc_free(dn);

    pos = dns_packet_copy(buf, len, pos, out, 4); if (!pos) return 1;
    if (!byte_isequal(out, 2, d->qtype)) return 1;
    if (!byte_isequal(out + 2, 2, DNS_C_IN)) return 1;

    return 0;
}

static void packetfree(struct dns_transmit *d) {
    if (!d->packet) return;
    alloc_free(d->packet);
    d->packet = 0;
}

static void queryfree(struct dns_transmit *d) {
    if (!d->query) return;
    alloc_free(d->query);
    d->query = 0;
}

static void socketfree(struct dns_transmit *d) {
    if (!d->s1) return;
    close(d->s1 - 1);
    d->s1 = 0;
    d->s1type = 0;
}

void dns_transmit_free(struct dns_transmit *d) {
    queryfree(d);
    socketfree(d);
    packetfree(d);
}

static int randombind(struct dns_transmit *d) {

    long long j;
    unsigned char port[2];
    long long pos = 0;

    if (d->s1type == XSOCKET_V4) pos = 0;
    if (d->s1type == XSOCKET_V6) pos = 16;

    for (j = 0;j < 10;++j) {
        uint16_pack_big(port, randommod(64510) + 1025);
        if (xsocket_bind(d->s1 - 1, d->s1type, d->localip + pos, port, d->scope_id) == 0) return 0;
    }
    byte_zero(port, 2);
    if (xsocket_bind(d->s1 - 1, d->s1type, d->localip + pos, port, d->scope_id) == 0) return 0;
    return -1;
}

static const long long timeouts[4] = { 1000, 3000, 11000, 45000 }; 

static int thisudp(struct dns_transmit *d) {

    const unsigned char *ip;

    socketfree(d);

    while (d->udploop < 4) {
        for (;d->curserver < 16; ++d->curserver) {
            ip = d->servers + 16 * d->curserver;
            if (!byte_isequal(ip, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {

                makequery(d);

                d->s1type = XSOCKET_V6;
                if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { 
                    d->s1type = XSOCKET_V4;
                }

                if (d->s1type == XSOCKET_V6 && d->flagipv4only) continue;

                d->s1 = 1 + xsocket_udp(d->s1type);
                if (!d->s1) { 
                    if (errno == EPROTONOSUPPORT) { dns_verbosity_queryfailed(d, 0); continue; }
                    dns_transmit_free(d);
                    return -1;
                }
	        if (randombind(d) == -1) {
                    if (errno == EPROTONOSUPPORT) { dns_verbosity_queryfailed(d, 0); continue; }
                    dns_transmit_free(d);
                    return -1;
                }

                if (xsocket_send(d->s1 - 1, d->s1type, d->query + 2, d->querylen - 2, ip, d->port, d->scope_id) == d->querylen - 2) {
                    dns_verbosity_querysent(d, 0);
                    d->deadline = milliseconds() + timeouts[d->udploop];
                    d->tcpstate = 0;
                    return 0;
                }
                dns_verbosity_queryfailed(d, 0);
                socketfree(d);
            }
        }

        ++d->udploop;
        d->curserver = 0;
    }

    dns_transmit_free(d); return -1;
}

static int firstudp(struct dns_transmit *d) {
    d->curserver = 0;
    return thisudp(d);
}

static int nextudp(struct dns_transmit *d) {
    dns_verbosity_queryfailed(d, 0);
    ++d->curserver;
    return thisudp(d);
}

static int thistcp(struct dns_transmit *d) {

    const unsigned char *ip;

    socketfree(d);
    packetfree(d);

    for (;d->curserver < 16; ++d->curserver) {
        ip = d->servers + 16 * d->curserver;
        if (!byte_isequal(ip, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
            makequery(d);

            d->s1type = XSOCKET_V6;
            if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { 
                d->s1type = XSOCKET_V4;
            }

            if (d->s1type == XSOCKET_V6 && d->flagipv4only) continue;

            d->s1 = 1 + xsocket_tcp(d->s1type);
            if (!d->s1) {
                if (errno == EPROTONOSUPPORT) { dns_verbosity_queryfailed(d, 1); continue; }
                dns_transmit_free(d);
                return -1;
            }
            if (randombind(d) == -1) {
                if (errno == EPROTONOSUPPORT) { dns_verbosity_queryfailed(d, 1); continue; }
                dns_transmit_free(d);
                return -1;
            }

            d->deadline = milliseconds() + 10000;
  
            if (xsocket_connect(d->s1 - 1, d->s1type, ip, d->port, d->scope_id) == 0) {
                d->pos = 0;
                d->tcpstate = 2;
                dns_verbosity_querysent(d, 1);
                return 0;
            }
            if ((errno == EINPROGRESS) || (errno == EWOULDBLOCK)) {
                d->tcpstate = 1;
                dns_verbosity_querysent(d, 1);
                return 0;
            }
            dns_verbosity_queryfailed(d, 1);
            socketfree(d);
        }
    }
    dns_transmit_free(d); return -1;
}

static int firsttcp(struct dns_transmit *d) {
    d->curserver = 0;
    return thistcp(d);
}

static int nexttcp(struct dns_transmit *d) {
    dns_verbosity_queryfailed(d, 1);
    ++d->curserver;
    return thistcp(d);
}

int dns_transmit_startext(struct dns_transmit *d, const unsigned char servers[256], int flagrecursive, int flagtcp, int flagipv4only, const unsigned char *q, const unsigned char qtype[2], const unsigned char localip[32], const unsigned char port[2], const unsigned char keys[512], const unsigned char pk[32], const unsigned char *suffix) {

    long long len, suffixlen = 0;

    dns_transmit_free(d);
    errno = EIO;

    /* suffix length */
    if (!suffix) suffix = (unsigned char *)"";
    suffixlen = dns_domain_length(suffix);

    /* length */
    len = dns_domain_length(q);

    /* allocate enough space */
    if (!keys) {
        d->paddinglen = 0;
        d->query = alloc(len + 18 + d->paddinglen);
    }
    else {
        d->paddinglen = 3 * 64 - (len + 16) % 64; /* padding MAX */
        d->query = alloc(dns_base32_bytessize(len + d->paddinglen + 44) + suffixlen + 73);
    }
    if (!d->query) return -1;

    /* init structure */
    byte_copy(d->qtype, 2, qtype);
    d->servers = servers;
    if (!localip) {
        byte_copy(d->localip, 16, xsocket_ANYIP4);
        byte_copy(d->localip + 16, 16, xsocket_ANYIP6);
    }
    else {
        byte_copy(d->localip, 32, localip);
    }
    d->udploop = flagrecursive ? 1 : 0;

    d->flagrecursive = flagrecursive;
    d->flagipv4only = flagipv4only;
    d->name = q;
    d->keys = keys;
    d->pk = pk;
    d->suffix = suffix;

    if (!port) {
        uint16_pack_big(d->port, 53);
    }
    else {
        byte_copy(d->port, 2, port);
    }

    if (len + 16 > 512 || flagtcp) return firsttcp(d);
    return firstudp(d);
}

int dns_transmit_start(struct dns_transmit *d, const unsigned char servers[256], int flagrecursive, const unsigned char *q, const unsigned char qtype[2], const unsigned char localip[32]) {
    return dns_transmit_startext(d, servers, flagrecursive, 0, 0, q, qtype, localip, 0, 0, 0, 0);
}


void dns_transmit_io(struct dns_transmit *d, struct pollfd *x, long long *deadline) {

    x->fd = d->s1 - 1;

    switch(d->tcpstate) {
        case 0: case 3: case 4: case 5:
            x->events = POLLIN;
            break;
        case 1: case 2:
            x->events = POLLOUT;
            break;
    }

    if (d->deadline < *deadline) *deadline = d->deadline;
}

int dns_transmit_get(struct dns_transmit *d, const struct pollfd *x, const long long when) {

  unsigned char udpbuf[4097];
  unsigned char ch;
  long long r;
  int fd;

  unsigned char ip[16];
  unsigned char port[2];

  errno = EIO;
  fd = d->s1 - 1;

  if (!x->revents) {
    if (when < d->deadline) return 0;
    errno = ETIMEDOUT;
    if (d->tcpstate == 0) return nextudp(d);
    return nexttcp(d);
  }

  if (d->tcpstate == 0) {
/*
have attempted to send UDP query to each server udploop times
have sent query to curserver on UDP socket s
*/
    r = xsocket_recv(fd,d->s1type,udpbuf,sizeof udpbuf,ip,port,0);
    if (r <= 0) {
      /* if (errno == ECONNREFUSED) if (d->udploop == 2) return 0; */
      return nextudp(d);
    }
    if (r + 1 > sizeof udpbuf) return 0;

    if (getquery(d, udpbuf, &r)) return 0;
    if (irrelevant(d,udpbuf,r)) return 0;
    if (serverwantstcp(udpbuf,r)) { dns_verbosity_queryfailedtc(d); return firsttcp(d); }
    if (serverfailed(udpbuf,r)) {
      /* if (d->udploop == 2) return 0; */
      return nextudp(d);
    }
    socketfree(d);

    d->packetlen = r;
    d->packet = alloc(d->packetlen);
    if (!d->packet) { dns_transmit_free(d); return -1; }
    byte_copy(d->packet,d->packetlen,udpbuf);
    queryfree(d);
    dns_verbosity_queryok(d);
    return 1;
  }

  if (d->tcpstate == 1) {
/*
have sent connection attempt to curserver on TCP socket s
pos not defined
*/
    if (!xsocket_connected(fd)) return nexttcp(d);
    d->pos = 0;
    d->tcpstate = 2;
    return 0;
  }

  if (d->tcpstate == 2) {
/*
have connection to curserver on TCP socket s
have sent pos bytes of query
*/
    r = write(fd,d->query + d->pos,d->querylen - d->pos);
    if (r <= 0) return nexttcp(d);
    d->pos += r;
    if (d->pos == d->querylen) {
      d->deadline = milliseconds() + 10000;
      d->tcpstate = 3;
    }
    return 0;
  }

  if (d->tcpstate == 3) {
/*
have sent entire query to curserver on TCP socket s
pos not defined
*/
    r = read(fd,&ch,1);
    if (r <= 0) return nexttcp(d);
    d->packetlen = ch;
    d->tcpstate = 4;
    return 0;
  }

  if (d->tcpstate == 4) {
/*
have sent entire query to curserver on TCP socket s
pos not defined
have received one byte of packet length into packetlen
*/
    r = read(fd,&ch,1);
    if (r <= 0) return nexttcp(d);
    d->packetlen <<= 8;
    d->packetlen += ch;
    d->tcpstate = 5;
    d->pos = 0;
    d->packet = alloc(d->packetlen);
    if (!d->packet) { dns_transmit_free(d); return -1; }
    return 0;
  }

  if (d->tcpstate == 5) {
/*
have sent entire query to curserver on TCP socket s
have received entire packet length into packetlen
packet is allocated
have received pos bytes of packet
*/
    r = read(fd,d->packet + d->pos,d->packetlen - d->pos);
    if (r <= 0) return nexttcp(d);
    d->pos += r;
    if (d->pos < d->packetlen) return 0;

    socketfree(d);
    if (getquery(d,d->packet,&d->packetlen)) return nexttcp(d);
    if (irrelevant(d,d->packet,d->packetlen)) return nexttcp(d);
    if (serverwantstcp(d->packet,d->packetlen)) { dns_verbosity_queryfailedtc(d); return nexttcp(d); }
    if (serverfailed(d->packet,d->packetlen)) return nexttcp(d);

    queryfree(d);
    dns_verbosity_queryok(d);
    return 1;
  }

  return 0;
}
