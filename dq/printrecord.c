#include "uint16_unpack_big.h"
#include "uint32_unpack_big.h"
#include "e.h"
#include "byte.h"
#include "dns.h"
#include "printrecord.h"
#include "iptostr.h"

static unsigned char *d = 0;

long long printrecord_cat(stralloc *out,const unsigned char *buf,long long  len,long long pos,const unsigned char *q,const unsigned char qtype[2])
{
  const unsigned char *x;
  unsigned char misc[20];
  crypto_uint16 datalen;
  crypto_uint16 u16;
  crypto_uint32 u32;
  long long  newpos;
  long long i;
  unsigned char ch;
  long long txtlen;

  pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,misc,10); if (!pos) return 0;
  datalen = uint16_unpack_big(misc + 8);
  newpos = pos + datalen;

  if (q) {
    if (!dns_domain_equal(d,q))
      return newpos;
    if (!byte_isequal(qtype,2,misc) && !byte_isequal(qtype,2,DNS_T_ANY))
      return newpos;
  }

  if (!dns_domain_todot_cat(out,d)) return 0;
  if (!stralloc_cats(out," ")) return 0;
  u32 = uint32_unpack_big(misc + 4);
  if (!stralloc_catnum(out,u32)) return 0;

  if (!byte_isequal(misc + 2,2,DNS_C_IN)) {
    if (!stralloc_cats(out," weird class\n")) return 0;
    return newpos;
  }

  x = 0;
  if (byte_isequal(misc,2,DNS_T_NS)) x = (unsigned char *)" NS ";
  if (byte_isequal(misc,2,DNS_T_PTR)) x = (unsigned char *)" PTR ";
  if (byte_isequal(misc,2,DNS_T_CNAME)) x = (unsigned char *)" CNAME ";
  if (x) {
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!stralloc_cats(out,x)) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_isequal(misc,2,DNS_T_MX)) {
    if (!stralloc_cats(out," MX ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,2); if (!pos) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    u16 = uint16_unpack_big(misc);
    if (!stralloc_catnum(out,u16)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_isequal(misc,2,DNS_T_SOA)) {
    if (!stralloc_cats(out," SOA ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,20); if (!pos) return 0;
    for (i = 0;i < 5;++i) {
      if (!stralloc_cats(out," ")) return 0;
      u32 = uint32_unpack_big(misc + 4 * i);
      if (!stralloc_catnum(out,u32)) return 0;
    }
  }
  else if (byte_isequal(misc,2,DNS_T_AAAA)) {
    if (datalen != 16) { errno = EPROTO; return 0; }
    if (!stralloc_cats(out," AAAA ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,16); if (!pos) return 0;
    if (!stralloc_cats(out,iptostr(0, misc))) return 0;
  }
  else if (byte_isequal(misc,2,DNS_T_TXT)) {
    if (pos + datalen > len) return -1;
    if (!stralloc_cats(out," TXT ")) return 0;
    txtlen = 0;
    for (i = 0;i < datalen;++i) {
      ch = buf[pos + i];
      if (!txtlen)
        txtlen = ch;
      else {
        --txtlen;
        if (ch < 32 || ch > 126) {
          misc[3] = '0' + (7 & ch); ch >>= 3;
          misc[2] = '0' + (7 & ch); ch >>= 3;
          misc[1] = '0' + (7 & ch);
          misc[0] = '\\';
          if (!stralloc_catb(out,misc,4)) return 0;
        }
        else {
          if (!stralloc_append(out,&ch)) return -1;
        }
      }
    }
    pos += datalen;
  }
  else if (byte_isequal(misc,2,DNS_T_SRV)) {
    if (!stralloc_cats(out," SRV ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,6); if (!pos) return 0;
    u16 = uint16_unpack_big(misc);
    if (!stralloc_catnum(out,u16)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    u16 = uint16_unpack_big(misc + 2);
    if (!stralloc_catnum(out,u16)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    u16 = uint16_unpack_big(misc + 4);
    if (!stralloc_catnum(out,u16)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_isequal(misc,2,DNS_T_A)) {
    if (datalen != 4) { errno = EPROTO; return 0; }
    if (!stralloc_cats(out," A ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,4); if (!pos) return 0;
    for (i = 0;i < 4;++i) {
      ch = misc[i];
      if (i) if (!stralloc_cats(out,".")) return 0;
      if (!stralloc_catnum(out,ch)) return 0;
    }
  }
  else {
    if (!stralloc_cats(out," ")) return 0;
    u16 = uint16_unpack_big(misc);
    if (!stralloc_catnum(out,u16)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    while (datalen--) {
      pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
      if ((misc[0] >= 33) && (misc[0] <= 126) && (misc[0] != '\\')) {
        if (!stralloc_catb(out,misc,1)) return 0;
      }
      else {
        ch = misc[0];
        misc[3] = '0' + (7 & ch); ch >>= 3;
        misc[2] = '0' + (7 & ch); ch >>= 3;
        misc[1] = '0' + (7 & ch);
        misc[0] = '\\';
        if (!stralloc_catb(out,misc,4)) return 0;
      }
    }
  }

  if (!stralloc_cats(out,"\n")) return 0;
  if (pos != newpos) { errno = EPROTO; return 0; }
  return newpos;
}

long long printrecord(stralloc *out,const unsigned char *buf,long long len,long long pos,const unsigned char *q,const unsigned char qtype[2])
{
  if (!stralloc_copys(out,"")) return 0;
  return printrecord_cat(out,buf,len,pos,q,qtype);
}
