#include "alloc.h"
#include "byte.h"
#include "case.h"
#include "e.h"
#include "dns.h"


long long dns_domain_length(const unsigned char *dn) {

    const unsigned char *x;
    unsigned char c;

     x = dn;
     while (c = *x++) {
         x += c;
     }
     return (x - dn);
}


void dns_domain_free(unsigned char **out) {
    if (*out) {
        alloc_free(*out);
        *out = 0;
    }
}

int dns_domain_copy(unsigned char **out, const unsigned char *in) {

    long long len;
    unsigned char *x;

    len = dns_domain_length(in);
    x = alloc(len);
    if (!x) return 0;
    byte_copy(x, len, in);
    if (*out) alloc_free(*out);
    *out = x;
    return 1;
}

int dns_domain_equal(const unsigned char *dn1, const unsigned char *dn2) {

    long long len;

    len = dns_domain_length(dn1);
    if (len != dns_domain_length(dn2)) return 0;
    return !case_diffb(dn1, len, dn2);
}

int dns_domain_suffix(const unsigned char *big, const unsigned char *little) {

    unsigned char c;

    for (;;) {
        if (dns_domain_equal(big, little)) return 1;
        c = *big++;
        if (!c) return 0;
        big += c;
    }
}

long long dns_domain_suffixpos(const unsigned char *big, const unsigned char *little) {

    const unsigned char *orig = big;
    unsigned char c;

    for (;;) {
        if (dns_domain_equal(big, little)) return (big - orig);
        c = *big++;
        if (!c) return 0;
        big += c;
    }
}

int dns_domain_fromdot(unsigned char **out,const unsigned char *buf,long long n)
{
  unsigned char label[63];
  long long labellen = 0; /* <= sizeof label */
  unsigned char name[255];
  long long namelen = 0; /* <= sizeof name */
  unsigned char ch;
  unsigned char *x;

  errno = EPROTO;

  if (n < 0) return 0;

  for (;;) {
    if (!n) break;
    ch = *buf++; --n;
    if (ch == '.') {
      if (labellen > 0) {
        if (namelen + labellen + 1 > sizeof name) return 0;
        name[namelen++] = labellen;
        byte_copy(name + namelen,labellen,label);
        namelen += labellen;
        labellen = 0;
      }
      continue;
    }
    if (ch == '\\') {
      if (!n) break;
      ch = *buf++; --n;
      if ((ch >= '0') && (ch <= '7')) {
        ch -= '0';
        if (n && (*buf >= '0') && (*buf <= '7')) {
          ch <<= 3;
          ch += *buf - '0';
          ++buf; --n;
          if (n && (*buf >= '0') && (*buf <= '7')) {
            ch <<= 3;
            ch += *buf - '0';
            ++buf; --n;
          }
        }
      }
    }
    if (labellen >= sizeof label) return 0;
    label[labellen++] = ch;
  }

  if (labellen > 0) {
    if (namelen + labellen + 1 > sizeof name) return 0;
    name[namelen++] = labellen;
    byte_copy(name + namelen,labellen,label);
    namelen += labellen;
    labellen = 0;
  }

  if (namelen + 1 > sizeof name) return 0;
  name[namelen++] = 0;

  x = alloc(namelen);
  if (!x) return 0;
  byte_copy(x,namelen,name);

  if (*out) alloc_free(*out);
  *out = x;
  return 1;
}

int dns_domain_fromdot_static(unsigned char *name,const unsigned char *buf,long long n)
{
  unsigned char label[63];
  long long labellen = 0; /* <= sizeof label */
  long long namelen = 0; /* <= sizeof name */
  unsigned char ch;

  errno = EPROTO;
  if (n < 0) return 0;
  byte_zero(name, 256);

  for (;;) {
    if (!n) break;
    ch = *buf++; --n;
    if (ch == '.') {
      if (labellen > 0) {
        if (namelen + labellen + 1 > 255) return 0;
        name[namelen++] = labellen;
        byte_copy(name + namelen,labellen,label);
        namelen += labellen;
        labellen = 0;
      }
      continue;
    }
    if (ch == '\\') {
      if (!n) break;
      ch = *buf++; --n;
      if ((ch >= '0') && (ch <= '7')) {
        ch -= '0';
        if (n && (*buf >= '0') && (*buf <= '7')) {
          ch <<= 3;
          ch += *buf - '0';
          ++buf; --n;
          if (n && (*buf >= '0') && (*buf <= '7')) {
            ch <<= 3;
            ch += *buf - '0';
            ++buf; --n;
          }
        }
      }
    }
    if (labellen >= sizeof label) return 0;
    label[labellen++] = ch;
  }

  if (labellen > 0) {
    if (namelen + labellen + 1 > 255) return 0;
    name[namelen++] = labellen;
    byte_copy(name + namelen,labellen,label);
    namelen += labellen;
    labellen = 0;
  }

  if (namelen + 1 > 255) return 0;
  name[namelen++] = 0;

  return 1;
}
