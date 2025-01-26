#include "crypto_uint16.h"
#include "e.h"
#include "byte.h"
#include "dns.h"
#include "printrecord.h"
#include "printpacket.h"

static unsigned char *d = 0;

#define X(s) if (!stralloc_cats(out,s)) return 0;
#define NUM(u) if (!stralloc_catnum(out,u)) return 0;

int printpacket_cat(stralloc *out, unsigned char *buf, long long len)
{
  crypto_uint16 xnumqueries;
  crypto_uint16 numanswers;
  crypto_uint16 numauthority;
  crypto_uint16 numglue;
  long long pos;
  unsigned char data[12];
  crypto_uint16 type;

  pos = dns_packet_copy(buf,len,0,data,12); if (!pos) return 0;

  xnumqueries = crypto_uint16_load_bigendian(data + 4);
  numanswers = crypto_uint16_load_bigendian(data + 6);
  numauthority = crypto_uint16_load_bigendian(data + 8);
  numglue = crypto_uint16_load_bigendian(data + 10);

  NUM(len)
  X(" bytes, ")
  NUM(xnumqueries)
  X("+")
  NUM(numanswers)
  X("+")
  NUM(numauthority)
  X("+")
  NUM(numglue)
  X(" records")

  if (data[2] & 128) X(", response")
  if (data[2] & 120) X(", weird op")
  if (data[2] & 4) X(", authoritative")
  if (data[2] & 2) X(", truncated")
  if (data[2] & 1) X(", weird rd")
  if (data[3] & 128) X(", weird ra")
  switch(data[3] & 15) {
    case 0: X(", noerror"); break;
    case 3: X(", nxdomain"); break;
    case 4: X(", notimp"); break;
    case 5: X(", refused"); break;
    default: X(", weird rcode");
  }
  if (data[3] & 112) X(", weird z")

  X("\n")

  while (xnumqueries) {
    --xnumqueries;
    X("query: ")

    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    pos = dns_packet_copy(buf,len,pos,data,4); if (!pos) return 0;

    if (!byte_isequal(data + 2,2,DNS_C_IN)) {
      X("weird class")
    }
    else {
      type = crypto_uint16_load_bigendian(data);
      NUM(type)
      X(" ")
      if (!dns_domain_todot_cat(out,d)) return 0;
    }
    X("\n")
  }

  for (;;) {
    if (numanswers) { --numanswers; X("answer: ") }
    else if (numauthority) { --numauthority; X("authority: ") }
    else if (numglue) { --numglue; X("additional: ") }
    else break;

    pos = printrecord_cat(out,buf,len,pos,0,0);
    if (!pos) return 0;
  }

  if (pos != len) { errno = EPROTO; return 0; }
  return 1;
}
