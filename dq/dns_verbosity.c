#include "stralloc.h"
#include "writeall.h"
#include "iptostr.h"
#include "porttostr.h"
#include "numtostr.h"
#include "e.h"
#include "uint16_unpack_big.h"
#include "byte.h"
#include "dns.h"

int dns_verbosity_flag = 1;
const char *dns_verbosity_message = "dns: info: ";

void dns_verbosity_setflag(int x) {
    dns_verbosity_flag = x;
}
void dns_verbosity_setmessage(const char *x) {
    dns_verbosity_message = x;
}

static stralloc out = {0};

void dns_verbosity_writehex(const char *message, const unsigned char *x, long long xlen) {

    if (dns_verbosity_flag < 3) return;
    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (!stralloc_cats(&out, message)) return;

    while (xlen > 0) {
        if (!stralloc_catb(&out, "0123456789abcdef" + ((*x >> 4) & 15), 1)) return;
        if (!stralloc_catb(&out, "0123456789abcdef" + (*x & 15), 1)) return;
        ++x; --xlen;
    }
    if (!stralloc_cats(&out, "\n")) return;
    writeall(2, out.s, out.len);
}

void dns_verbosity_writedomain(const char *message, unsigned char *x) {

    if (dns_verbosity_flag < 3) return;
    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (!stralloc_cats(&out, message)) return;
    if (!dns_domain_todot_cat(&out, x)) return;
    if (!stralloc_cats(&out, "\n")) return;
    writeall(2, out.s, out.len);
}

static const unsigned char *qtypetostr(const unsigned char *qtype) {

    crypto_uint16 u16;

    if (byte_isequal(qtype, 2, DNS_T_A)) return (unsigned char *)"A";
    if (byte_isequal(qtype, 2, DNS_T_NS)) return (unsigned char *)"NS";
    if (byte_isequal(qtype, 2, DNS_T_MX)) return (unsigned char *)"MX";
    if (byte_isequal(qtype, 2, DNS_T_ANY)) return (unsigned char *)"ANY";
    if (byte_isequal(qtype, 2, DNS_T_PTR)) return (unsigned char *)"PTR";
    if (byte_isequal(qtype, 2, DNS_T_TXT)) return (unsigned char *)"TXT";
    if (byte_isequal(qtype, 2, DNS_T_SOA)) return (unsigned char *)"SOA";
    if (byte_isequal(qtype, 2, DNS_T_SRV)) return (unsigned char *)"SRV";
    if (byte_isequal(qtype, 2, DNS_T_AAAA)) return (unsigned char *)"AAAA";
    if (byte_isequal(qtype, 2, DNS_T_PTR)) return (unsigned char *)"PTR";
    if (byte_isequal(qtype, 2, DNS_T_CNAME)) return (unsigned char *)"CNAME";

    u16 = uint16_unpack_big(qtype);
    return (const unsigned char *)numtostr(0, u16);

}

void dns_verbosity_resolving(const char *x) {

    if (dns_verbosity_flag < 3) return;
    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (!stralloc_cats(&out, "resolving: ")) return;
    if (!stralloc_cats(&out, x)) return;
    if (!stralloc_cats(&out, "\n")) return;
    writeall(2, out.s, out.len);
}

void dns_verbosity_resolved(struct dns_data *r, const char *x) {

    long long j;

    if (dns_verbosity_flag < 3) return;

    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (!stralloc_cats(&out, "resolved: ")) return;
    if (!stralloc_cats(&out, x)) return;
    if (!stralloc_cats(&out, ": ")) return;
    if (!stralloc_cat(&out, &r->fqdn)) return;
    if (!stralloc_cats(&out, " ")) return;
    for (j = 0; j + 16 <= r->result.len; j += 16) {
        if (!stralloc_cats(&out, iptostr(0, r->result.s + j))) return;
        if (!stralloc_cats(&out, ",")) return;
    }
    out.len -= 1;
    if (!stralloc_cats(&out, "\n")) return;
    writeall(2, out.s, out.len);
}


void dns_verbosity_querysent(struct dns_transmit *d, int flagtcp) {

    if (dns_verbosity_flag < 3) return;
    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (DNS_HASKEY(d)) {
        if (!stralloc_cats(&out, "DNSCurve query: ")) return;
    }
    else {
        if (!stralloc_cats(&out, "DNS query: ")) return;
    }
    if (!dns_domain_todot_cat(&out, d->name)) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, qtypetostr(d->qtype))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (flagtcp) {
        if (!stralloc_cats(&out, "TCP ")) return;
    }
    else {
        if (!stralloc_cats(&out, "UDP ")) return;
    }
    if (!stralloc_cats(&out, iptostr(0, d->servers + 16 * d->curserver))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, porttostr(0, d->port))) return;
    if (!stralloc_cats(&out, ": sent\n")) return;
    writeall(2, out.s, out.len);
}

void dns_verbosity_queryfailed(struct dns_transmit *d, int flagtcp) {

    if (dns_verbosity_flag < 2) return;

    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (DNS_HASKEY(d)) {
        if (!stralloc_cats(&out, "DNSCurve query: ")) return;
    }
    else {
        if (!stralloc_cats(&out, "DNS query: ")) return;
    }
    if (!dns_domain_todot_cat(&out, d->name)) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, qtypetostr(d->qtype))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (flagtcp) {
        if (!stralloc_cats(&out, "TCP ")) return;
    }
    else {
        if (!stralloc_cats(&out, "UDP ")) return;
    }
    if (!stralloc_cats(&out, iptostr(0, d->servers + 16 * d->curserver))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, porttostr(0, d->port))) return;
    if (!stralloc_cats(&out, ": failed: ")) return;
    if (!stralloc_cats(&out, e_str(errno))) return;
    if (!stralloc_cats(&out, "\n")) return;
    writeall(2, out.s, out.len);
}

void dns_verbosity_queryfailedtc(struct dns_transmit *d) {

    if (dns_verbosity_flag < 2) return;

    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (DNS_HASKEY(d)) {
        if (!stralloc_cats(&out, "DNSCurve query: ")) return;
    }
    else {
        if (!stralloc_cats(&out, "DNS query: ")) return;
    }
    if (!dns_domain_todot_cat(&out, d->name)) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, qtypetostr(d->qtype))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (d->tcpstate > 0) {
        if (!stralloc_cats(&out, "TCP ")) return;
    }
    else {
        if (!stralloc_cats(&out, "UDP ")) return;
    }
    if (!stralloc_cats(&out, iptostr(0, d->servers + 16 * d->curserver))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, porttostr(0, d->port))) return;
    if (!stralloc_cats(&out, ": failed: truncated\n")) return;
    writeall(2, out.s, out.len);
}

void dns_verbosity_queryok(struct dns_transmit *d) {

    if (dns_verbosity_flag < 3) return;
    
    if (!stralloc_copys(&out, dns_verbosity_message)) return;
    if (DNS_HASKEY(d)) {
        if (!stralloc_cats(&out, "DNSCurve query: ")) return;
    }
    else {
        if (!stralloc_cats(&out, "DNS query: ")) return;
    }
    if (!dns_domain_todot_cat(&out, d->name)) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, qtypetostr(d->qtype))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (d->tcpstate > 0) {
        if (!stralloc_cats(&out, "TCP ")) return;
    }
    else {
        if (!stralloc_cats(&out, "UDP ")) return;
    }
    if (!stralloc_cats(&out, iptostr(0, d->servers + 16 * d->curserver))) return;
    if (!stralloc_cats(&out, " ")) return;
    if (!stralloc_cats(&out, porttostr(0, d->port))) return;
    if (!stralloc_cats(&out, ": received\n")) return;
    writeall(2, out.s, out.len);
}
