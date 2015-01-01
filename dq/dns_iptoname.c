#include "byte.h"
#include "numtostr.h"
#include "dns.h"

static char *dns_iptoname4(char *name, const unsigned char *ip) {

    long long i,j;
    char strnum[NUMTOSTR_LEN], *x;

    j = 0;
    for (i = 3; i >= 0; --i) {
        x = numtostr(strnum, ip[i]);
        while (*x) name[j++] = *x++;
        name[j++] = '.';
    }
    byte_copy(name + j, 13, "in-addr.arpa");
    return name;
}

static char *dns_iptoname6(char *name, const unsigned char *ip) {

    long long i,j;

    j = 0;
    for (i = 15; i >= 0; --i) {
        name[j++] = "0123456789abcdef"[(ip[i] >> 0) & 15]; name[j++] = '.';
        name[j++] = "0123456789abcdef"[(ip[i] >> 4) & 15]; name[j++] = '.';
    }
    byte_copy(name + j, 9, "ip6.arpa");
    return name;
}

char *dns_iptoname(char *namebuf, const unsigned char *ip) {

    static char staticbuf[DNS_IPTONAME_LEN];

    if (!namebuf) namebuf = staticbuf; /* not thread-safe */

    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) {
        return dns_iptoname4(namebuf, ip + 12);
    }
    return dns_iptoname6(namebuf, ip);
}
