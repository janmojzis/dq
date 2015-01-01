#include "e.h"
#include "byte.h"
#include "dns.h"

long long dns_packet_copy(const unsigned char *buf, long long len, long long pos, unsigned char *out, long long outlen) {

    while (outlen > 0) {
        if (pos >= len) { errno = EPROTO; return 0; }
        *out = buf[pos++];
        ++out; --outlen;
    }
    return pos;
}

long long dns_packet_skipname(const unsigned char *buf, long long len, long long pos) {

    unsigned char ch;

    for (;;) {
        if (pos >= len) break;
        ch = buf[pos++];
        if (ch >= 192) return pos + 1;
        if (ch >= 64) break;
        if (!ch) return pos;
        pos += ch;
    }

    errno = EPROTO;
    return 0;
}

long long dns_packet_getname(const unsigned char *buf, long long len, long long pos, unsigned char **d) {

    long long loop = 0;
    long long state = 0;
    long long firstcompress = 0;
    long long where;
    unsigned char ch;
    unsigned char name[255];
    long long namelen = 0;

    for (;;) {
        if (pos >= len) goto PROTO; ch = buf[pos++];
        if (++loop >= 1000) goto PROTO;

        if (state > 0) {
            if (namelen + 1 > sizeof name) goto PROTO; name[namelen++] = ch;
            --state;
        }
        else {
            while (ch >= 192) {
                where = ch; where -= 192; where <<= 8;
                if (pos >= len) goto PROTO; ch = buf[pos++];
                if (!firstcompress) firstcompress = pos;
                pos = where + ch;
                if (pos >= len) goto PROTO; ch = buf[pos++];
                if (++loop >= 1000) goto PROTO;
            }
            if (ch >= 64) goto PROTO;
            if (namelen + 1 > sizeof name) goto PROTO; name[namelen++] = ch;
            if (!ch) break;
            state = ch;
        }
    }

    if (!dns_domain_copy(d, name)) return 0;

    if (firstcompress) return firstcompress;
    return pos;

PROTO:
    errno = EPROTO;
    return 0;
}

long long dns_packet_getname_static(const unsigned char *buf, long long len, long long pos, unsigned char *name) {

    long long loop = 0;
    long long state = 0;
    long long firstcompress = 0;
    long long where;
    unsigned char ch;
    long long namelen = 0;

    byte_zero(name, 256);

    for (;;) {
        if (pos >= len) goto PROTO; ch = buf[pos++];
        if (++loop >= 1000) goto PROTO;

        if (state > 0) {
            if (namelen + 1 > 255) goto PROTO; name[namelen++] = ch;
            --state;
        }
        else {
            while (ch >= 192) {
                where = ch; where -= 192; where <<= 8;
                if (pos >= len) goto PROTO; ch = buf[pos++];
                if (!firstcompress) firstcompress = pos;
                pos = where + ch;
                if (pos >= len) goto PROTO; ch = buf[pos++];
                if (++loop >= 1000) goto PROTO;
            }
            if (ch >= 64) goto PROTO;
            if (namelen + 1 > 255) goto PROTO; name[namelen++] = ch;
            if (!ch) break;
            state = ch;
        }
    }

    if (firstcompress) return firstcompress;
    return pos;

PROTO:
    errno = EPROTO;
    return 0;
}
