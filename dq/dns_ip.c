#include "alloc.h"
#include "byte.h"
#include "crypto_uint16.h"
#include "uint16_unpack_big.h"
#include "base32decode.h"
#include "hexdecode.h"
#include "case.h"
#include "str.h"
#include "stralloc.h"
#include "strtoip.h"
#include "milliseconds.h"
#include "dns.h"

static int dns_curvecpkey_parse(struct dns_data *r, const unsigned char *d) {

    long long pos = 0;
    long long i;
    unsigned char c;
    unsigned char key[32];
    unsigned char ext[16];

    if (r->curvecpkey) return 0;

    for (;;) {
        c = d[pos++];
        if (!c) break;
        if (c == 54 && byte_isequal(d + pos, 3, "uz7") && base32decode(key, sizeof key, d + pos + 3, 51)) {
            pos += c;
            c = d[pos++];
            if (!c) break;
            if (c >= 32 && hexdecode(ext, sizeof ext, d + pos, 32)) {
                if (c == 32 || r->curvecpselector == 0) {
                    r->curvecpkey = alloc(48);
                    if (!r->curvecpkey) return -1;
                    byte_copy(r->curvecpkey, 32, key);
                    byte_copy(r->curvecpkey + 32, 16, ext);
                    return 0;
                }
                if (d[pos + 32] == '/') {
                    for (i = 33; i < c; ++i) {
                        if (!case_diffb(d + pos + i, 1, &r->curvecpselector)) {
                            r->curvecpkey = alloc(48);
                            if (!r->curvecpkey) return -1;
                            byte_copy(r->curvecpkey, 32, key);
                            byte_copy(r->curvecpkey + 32, 16, ext);
                            return 0;
                        }
                    }
                }
            }
        }
        pos += c;
    }
    return 0;
}

static int dns_dnscurvekey_parse(struct dns_data *r, const unsigned char *d) {

    long long pos = 0;
    unsigned char c;
    unsigned char key[32];

    if (r->dnscurvekey) return 0;

    for (;;) {
        c = d[pos++];
        if (!c) break;
        if (c == 54 && byte_isequal(d + pos, 3, "uz5") && base32decode(key, sizeof key, d + pos + 3, 51)) {
            r->dnscurvekey = alloc(32);
            if (!r->dnscurvekey) return -1;
            byte_copy(r->dnscurvekey, 32, key);
            return 0;
        }
        pos += c;
    }
    return 0;
}


static int ip_packet(struct dns_data *r, unsigned char *buf, long long len) {

    crypto_uint16 numanswers;
    crypto_uint16 numauthority;
    crypto_uint16 datalen;
    long long pos, newpos;
    unsigned char data[16];
    unsigned char d[256];

    /* header */
    pos = dns_packet_copy(buf, len, 0, data, 12); if (!pos) return -1;
    numanswers = uint16_unpack_big(data + 6);
    numauthority = uint16_unpack_big(data + 8);
    pos = dns_packet_getname_static(buf, len, pos, d); if (!pos) return -1;
    pos += 4;
    if (dns_dnscurvekey_parse(r, d) == -1) return -1;
    if (dns_curvecpkey_parse(r, d) == -1) return -1;

    while (numanswers--) {
        pos = dns_packet_skipname(buf, len, pos); if (!pos) return -1;
        pos = dns_packet_copy(buf, len, pos, data, 10); if (!pos) return -1;
        datalen = uint16_unpack_big(data + 8);
        newpos = pos + datalen;

        /* CNAME answers */
        if (byte_isequal(data, 2, DNS_T_CNAME)) {
            if (byte_isequal(data + 2, 2, DNS_C_IN)) {
                if (!dns_packet_getname_static(buf, len, pos, d)) return -1;
                if (dns_curvecpkey_parse(r, d) == -1) return -1; 
            }
        }
        /* A answers */
        else if (byte_isequal(data, 2, DNS_T_A)) {
            if (byte_isequal(data + 2, 2, DNS_C_IN)) {
                if (datalen == 4) {
                    if (!dns_packet_copy(buf, len, pos, data + 12, 4)) return -1;
                    byte_copy(data, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
                    if (!stralloc_catb(&r->result, data, 16)) return -1;
                }
            }
        }
        /* AAAA answers */
        else if (byte_isequal(data, 2, DNS_T_AAAA)) {
            if (byte_isequal(data + 2, 2, DNS_C_IN)) {
                if (datalen == 16) {
                    if (!dns_packet_copy(buf, len, pos, data, 16)) return -1;
                    if (!stralloc_catb(&r->result, data, 16)) return -1;
                }
            }
        }
        pos = newpos;
    }

    while (numauthority--) {
        pos = dns_packet_skipname(buf, len, pos); if (!pos) return -1;
        pos = dns_packet_copy(buf, len, pos, data, 10); if (!pos) return -1;
        datalen = uint16_unpack_big(data + 8);
        newpos = pos + datalen;

        /* NS authority */
        if (byte_isequal(data, 2, DNS_T_NS)) {
            if (byte_isequal(data + 2, 2, DNS_C_IN)) {
                if (!dns_packet_getname_static(buf, len, pos, d)) return -1;
                if (dns_curvecpkey_parse(r, d) == -1) return -1;
            }
        }
        pos = newpos;
    }

    return 0;
}

struct dns_transmit dns_resolve_tx0 = {0};
struct dns_transmit dns_resolve_tx1 = {0};

static int resolve2(struct dns_data *d, const unsigned char *q, const unsigned char qtype0[2], const unsigned char qtype1[2]) {

    long long deadline, stamp, timeout, max;
    unsigned char servers[256];
    struct pollfd x[2];
    int r;

    if (dns_resolvconfip(servers) == -1) return -1;
    if (dns_transmit_start(&dns_resolve_tx0, servers, 1, q, qtype0, 0) == -1) return -1;
    if (dns_transmit_start(&dns_resolve_tx1, servers, 1, q, qtype1, 0) == -1) return -1;

    for (;;) {

        stamp = milliseconds();
        deadline = 120000 + stamp;
        dns_transmit_io(&dns_resolve_tx0, &x[0], &deadline);
        dns_transmit_io(&dns_resolve_tx1, &x[1], &deadline);
        timeout = deadline - stamp;
        if (timeout <= 0) timeout = 20;
        poll(x, 2, timeout);

        r = dns_transmit_get(&dns_resolve_tx0, &x[0], stamp);
        if (r == -1) return -1;
        if (r == 1) {
            if (ip_packet(d, dns_resolve_tx0.packet, dns_resolve_tx0.packetlen) == -1) return -1;
            dns_transmit_free(&dns_resolve_tx0);
            byte_copy(&dns_resolve_tx0, sizeof (struct dns_transmit), &dns_resolve_tx1);
            byte_zero(&dns_resolve_tx1, sizeof (struct dns_transmit));
            break;
        }

        r = dns_transmit_get(&dns_resolve_tx1, &x[1], stamp);
        if (r == -1) return -1;
        if (r == 1) {
            if (ip_packet(d, dns_resolve_tx1.packet, dns_resolve_tx1.packetlen) == -1) return -1;
            break;
        }
    }

    max = 3000 + milliseconds();

    for (;;) {
        stamp = milliseconds();
        if (stamp > max) return 0;
        deadline = max;
        dns_transmit_io(&dns_resolve_tx0, x, &deadline);
        timeout = deadline - stamp;
        if (timeout <= 0) timeout = 20;
        poll(x, 1, timeout);

        r = dns_transmit_get(&dns_resolve_tx0, x, stamp);
        if (r == -1) return -1;
        if (r == 1) {
            if (ip_packet(d, dns_resolve_tx0.packet, dns_resolve_tx0.packetlen) == -1) return -1;
            return 0;
        }
    }
}



int dns_ip(struct dns_data *r, const char *name) {

    unsigned char ip[16];

    if (!dns_domain_fromdot(&r->name, (unsigned char *)name, str_len(name))) return -1;

    if (strtoip(ip, name)) {
        if (!stralloc_copyb(&r->result, ip, 16)) return -1;
        return 0;
    }
    if (!stralloc_copys(&r->result, "")) return -1;

    if (resolve2(r, r->name, DNS_T_AAAA, DNS_T_A) == -1) return -1;
    dns_transmit_free(&dns_resolve_tx0);
    dns_transmit_free(&dns_resolve_tx1);

    if (r->fqdn.len == 0) {
        if (!stralloc_copys(&r->fqdn, name)) return -1;
        if (!stralloc_0(&r->fqdn)) return -1;
    }

    dns_sortip(r->result.s, r->result.len);
    return 0;
}

int dns_ip4(struct dns_data *r, const char *name) {

    unsigned char ip[16];

    if (!dns_domain_fromdot(&r->name, (unsigned char *)name, str_len(name))) return -1;

    if (strtoip4(ip, name)) {
        if (!stralloc_copyb(&r->result, ip, 16)) return -1;
        return 0;
    }
    if (!stralloc_copys(&r->result, "")) return -1;

    /* A */
    if (dns_resolve(r->name, DNS_T_A) == -1) return -1;
    if (ip_packet(r, dns_resolve_tx.packet, dns_resolve_tx.packetlen) == -1) return -1;
    dns_transmit_free(&dns_resolve_tx);

    if (r->fqdn.len == 0) {
        if (!stralloc_copys(&r->fqdn, name)) return -1;
        if (!stralloc_0(&r->fqdn)) return -1;
    }

    dns_sortip(r->result.s, r->result.len);
    return 0;
}

int dns_ip6(struct dns_data *r, const char *name) {

    unsigned char ip[16];

    if (!dns_domain_fromdot(&r->name, (unsigned char *)name, str_len(name))) return -1;

    if (strtoip6(ip, name)) {
        if (!stralloc_copyb(&r->result, ip, 16)) return -1;
        return 0;
    }
    if (!stralloc_copys(&r->result, "")) return -1;

    /* AAAA */
    if (dns_resolve(r->name, DNS_T_AAAA) == -1) return -1;
    if (ip_packet(r, dns_resolve_tx.packet, dns_resolve_tx.packetlen) == -1) return -1;
    dns_transmit_free(&dns_resolve_tx);

    if (r->fqdn.len == 0) {
        if (!stralloc_copys(&r->fqdn, name)) return -1;
        if (!stralloc_0(&r->fqdn)) return -1;
    }

    dns_sortip(r->result.s, r->result.len);
    return 0;
}
