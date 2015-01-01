#include "stralloc.h"
#include "alloc.h"
#include "byte.h"
#include "dns.h"

void dns_data_free(struct dns_data *r) {

    dns_domain_free(&r->name);
    stralloc_free(&r->result);
    stralloc_free(&r->fqdn);
    if (r->curvecpkey) alloc_free(r->curvecpkey);
    if (r->dnscurvekey) alloc_free(r->dnscurvekey);
    byte_zero(r, sizeof(struct dns_data));

    return;
}
