#include <poll.h>
#include "milliseconds.h"
#include "byte.h"
#include "e.h"
#include "dns.h"

struct dns_transmit dns_resolve_tx = {0};

int dns_resolve(const unsigned char *q, const unsigned char qtype[2]) {

    long long deadline, stamp, timeout;
    unsigned char servers[256];
    struct pollfd x[1];
    int r;

    if (dns_resolvconfip(servers) == -1) return -1;
    if (dns_transmit_start(&dns_resolve_tx, servers, 1, q, qtype, 0) == -1) return -1;

    for (;;) {
        stamp = milliseconds();
        deadline = 120000 + stamp;;
        dns_transmit_io(&dns_resolve_tx, x, &deadline);
        timeout = deadline - stamp;
        if (timeout <= 0) timeout = 20;
        poll(x, 1, timeout);
        r = dns_transmit_get(&dns_resolve_tx, x, stamp);
        if (r == -1) return -1;
        if (r == 1) return 0;
    }
}
