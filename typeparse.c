#include "strtonum.h"
#include "uint16_pack_big.h"
#include "case.h"
#include "dns.h"
#include "byte.h"
#include "typeparse.h"

int typeparse(unsigned char *type, const char *s) {

    long long l;

    if (!s) return 0;

    if (strtonum(&l, s) && l > 0 && l <= 65535) {
        uint16_pack_big(type, l);
    }
    else if (case_equals(s, "a")) byte_copy(type, 2, DNS_T_A);
    else if (case_equals(s, "ns")) byte_copy(type, 2, DNS_T_NS);
    else if (case_equals(s, "mx")) byte_copy(type, 2, DNS_T_MX);
    else if (case_equals(s, "any")) byte_copy(type, 2, DNS_T_ANY);
    else if (case_equals(s, "ptr")) byte_copy(type, 2, DNS_T_PTR);
    else if (case_equals(s, "txt")) byte_copy(type, 2, DNS_T_TXT);
    else if (case_equals(s, "soa")) byte_copy(type, 2, DNS_T_SOA);
    else if (case_equals(s, "srv")) byte_copy(type, 2, DNS_T_SRV);
    else if (case_equals(s, "aaaa")) byte_copy(type, 2, DNS_T_AAAA);
    else if (case_equals(s, "axfr")) byte_copy(type, 2, DNS_T_AXFR);
    else if (case_equals(s, "cname")) byte_copy(type, 2, DNS_T_CNAME);
    else return 0;
    return 1;
}
