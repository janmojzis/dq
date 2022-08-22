#include "stralloc.h"
#include "case.h"
#include "byte.h"
#include "str.h" 
#include "dns.h"


static int doit(stralloc *work,const unsigned char *rule)
{
  unsigned char ch;
  long long colon;
  long long prefixlen;

  ch = *rule++;
  if ((ch != '?') && (ch != '=') && (ch != '*') && (ch != '-')) return 1;
  colon = str_chr((char *)rule,':');
  if (!rule[colon]) return 1;

  if (work->len < colon) return 1;
  prefixlen = work->len - colon;
  if ((ch == '=') && prefixlen) return 1;
  if (case_diffb(rule,colon,work->s + prefixlen)) return 1;
  if (ch == '?') {
    if (byte_chr(work->s,prefixlen,':') < prefixlen) return 1; /* IPv6 */
    if (byte_chr(work->s,prefixlen,'.') < prefixlen) return 1;
    if (byte_chr(work->s,prefixlen,'[') < prefixlen) return 1;
    if (byte_chr(work->s,prefixlen,']') < prefixlen) return 1;
  }

  work->len = prefixlen;
  if (ch == '-') work->len = 0;
  return stralloc_cats(work,rule + colon + 1);
}

static int dns_ip_qualify_rules(struct dns_data *out,stralloc *fqdn,const char *in,const stralloc *rules, int (*op)(struct dns_data *, const char *))
{
  long long i;
  long long j;
  long long plus;
  long long fqdnlen;

  if (!stralloc_copys(fqdn,in)) return -1;

  for (j = i = 0;j < rules->len;++j)
    if (!rules->s[j]) {
      if (!doit(fqdn,rules->s + i)) return -1;
      i = j + 1;
    }

  fqdnlen = fqdn->len;
  plus = byte_chr(fqdn->s,fqdnlen,'+');
  fqdn->s[fqdn->len] = 0;
  if (plus >= fqdnlen)
    return op(out,(char *)fqdn->s);

  i = plus + 1;
  for (;;) {
    j = byte_chr(fqdn->s + i,fqdnlen - i,'+');
    byte_copy(fqdn->s + plus,j,fqdn->s + i);
    fqdn->len = plus + j;
    fqdn->s[fqdn->len] = 0;
    if (op(out,(char *)fqdn->s) == -1) return -1;
    if (out->result.len) return 0;
    i += j;
    if (i >= fqdnlen) return 0;
    ++i;
  }
}


int dns_ip_qualify(struct dns_data *out, const char *in) {

    stralloc rules = {0};
    int r;

    dns_verbosity_resolving(in);
    if (dns_resolvconfrewrite(&rules) == -1) return -1;
    r = dns_ip_qualify_rules(out, &out->fqdn, in, &rules, dns_ip);
    stralloc_free(&rules);
    dns_verbosity_resolved(out, in);
    return r;
}

int dns_ip4_qualify(struct dns_data *out, const char *in) {

    stralloc rules = {0};
    int r;

    dns_verbosity_resolving(in);
    if (dns_resolvconfrewrite(&rules) == -1) return -1;
    r = dns_ip_qualify_rules(out, &out->fqdn, in, &rules, dns_ip4);
    stralloc_free(&rules);
    dns_verbosity_resolved(out, in);
    return r;
}

int dns_ip6_qualify(struct dns_data *out, const char *in) {

    stralloc rules = {0};
    int r;

    dns_verbosity_resolving(in);
    if (dns_resolvconfrewrite(&rules) == -1) return -1;
    r = dns_ip_qualify_rules(out, &out->fqdn, in, &rules, dns_ip6);
    stralloc_free(&rules);
    dns_verbosity_resolved(out, in);
    return r;
}
