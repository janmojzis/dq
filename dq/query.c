#include "e.h"
#include "roots.h"
#include "log.h"
#include "case.h"
#include "cache.h"
#include "byte.h"
#include "dns.h"
#include "uint32_unpack_big.h"
#include "uint16_unpack_big.h"
#include "alloc.h"
#include "response.h"
#include "query.h"
#include "strtoip.h"
#include "iptostr.h"
#include "xsocket.h"
#include "crypto.h"
#include "purge.h"

static unsigned char secretkey[32];
static unsigned char publickey[32];

void query_init(const unsigned char *sk)
{
  byte_copy(secretkey,32,sk);
  crypto_scalarmult_curve25519_base(publickey, secretkey);
  log_dnscurvekey(publickey);
  return;
}

void query_purge(void) {
    purge(secretkey, sizeof secretkey);
    purge(publickey, sizeof publickey);
}

static int flagforwardonly = 0;

void query_forwardonly(void)
{
  flagforwardonly = 1;
}

static int flagtcponly = 0;

void query_tcponly(void) {
    flagtcponly = 1;
}

static int flagipv4only = 0;

void query_ipv4only(void) {
    flagipv4only = 1;
}

static crypto_uint32 minttl = 0;

void query_minttl(long long x) {
    if (x < 0) x = 0;
    if (x > 86400) x = 86400;
    minttl = x;
}

unsigned char remoteport[2] = { 0, 53 };
void query_remoteport(unsigned char *port) {
    byte_copy(remoteport, 2, port);
}

static int flagdnscurvetype1 = 1;
static int flagdnscurvetype2 = 2;

void query_dnscurvetype(char *x)
{
  if (!x) return;

  if (*x == '1') {
    /* streamlined only */
    flagdnscurvetype1 = 1;
    flagdnscurvetype2 = 0;
  }
  else if (*x == '2') {
    /* txt only */
    flagdnscurvetype1 = 2;
    flagdnscurvetype2 = 0;
  }
  else {
    /* mixed */
    flagdnscurvetype1 = 1;
    flagdnscurvetype2 = 2;
  }
}

static void cachegeneric(const unsigned char type[2],const unsigned char *d,const unsigned char *data,long long datalen,crypto_uint32 ttl, unsigned char flagns)
{
  long long len;
  unsigned char key[257];

  len = dns_domain_length(d);
  if (len > 255) return;

  byte_copy(key,2,type);
  byte_copy(key + 2,len,d);
  case_lowerb(key + 2,len);

  cache_set(key,len + 2,data,datalen,ttl,flagns);
}

static void cachegeneric2(const unsigned char type[2],const unsigned char dtype[2], const unsigned char *d,const unsigned char *data,long long datalen,crypto_uint32 ttl, unsigned char flagns)
{
  long long len;
  unsigned char key[259];

  len = dns_domain_length(d);
  if (len > 255) return;

  byte_copy(key,2,type);
  byte_copy(key + 2,len,d);
  byte_copy(key + 2 + len,2,dtype);
  case_lowerb(key + 2,len);

  cache_set(key,len + 4,data,datalen,ttl,flagns);
}


static unsigned char save_buf[8192];
static long long save_len;
static long long save_ok;

static void save_start(void)
{
  save_len = 0;
  save_ok = 1;
}

static void save_data(const unsigned char *buf,long long len)
{
  if (!save_ok) return;
  if (len > (sizeof save_buf) - save_len) { save_ok = 0; return; }
  byte_copy(save_buf + save_len,len,buf);
  save_len += len;
}

static void save_finish(const unsigned char type[2],const unsigned char *d,crypto_uint32 ttl,unsigned char flagns)
{
  if (!save_ok) return;
  cachegeneric(type,d,save_buf,save_len,ttl,flagns);
}

static int typematch(const unsigned char rtype[2],const unsigned char qtype[2])
{
  return byte_isequal(qtype,2,rtype) || byte_isequal(qtype,2,DNS_T_ANY);
}

static long long ttlget(unsigned char buf[4])
{
  crypto_uint32 ttl;

  ttl=uint32_unpack_big(buf);
  if (ttl < minttl) ttl = minttl;
  if (ttl > 1000000000) return 0;
  if (ttl > 604800) return 604800;
  return ttl;
}


static void cleanup(struct query *z)
{
  int j;
  int k;

  dns_transmit_free(&z->dt);
  for (j = 0;j < QUERY_MAXALIAS;++j)
    dns_domain_free(&z->alias[j]);
  for (j = 0;j < QUERY_MAXLEVEL;++j) {
    dns_domain_free(&z->name[j]);
    for (k = 0;k < QUERY_MAXNS;++k)
      dns_domain_free(&z->ns[j][k]);
  }
}

static int rqa(struct query *z)
{
  int i;

  for (i = QUERY_MAXALIAS - 1;i >= 0;--i)
    if (z->alias[i]) {
      if (!response_query(z->alias[i],z->type,z->class)) return 0;
      while (i > 0) {
        if (!response_cname(z->alias[i],z->alias[i - 1],z->aliasttl[i])) return 0;
        --i;
      }
      if (!response_cname(z->alias[0],z->name[0],z->aliasttl[0])) return 0;
      return 1;
    }

  if (!response_query(z->name[0],z->type,z->class)) return 0;
  return 1;
}

static int dtis(char *out, long long outlen, const unsigned char *d) {

    long long pos = 0;
    char ch;
    char ch2;

    if (!*d) return 0;

    for (;;) {
        ch = *d++;
        while (ch--) {
            ch2 = *d++;
            if (((ch2 >= '0') && (ch2 <= '9')) || (ch2 == ':')) {
                if (pos >= outlen) return 0;
                out[pos++] = ch2;
                continue;
            }
            return 0;
        }   
        if (!*d) {
            if (pos >= outlen) return 0;
            out[pos++] = 0;
            return 1;
        }   
        if (pos >= outlen) return 0;
        out[pos++] = '.';
    }
    return 0;
}

static int globalip(unsigned char *d,unsigned char ip[16])
{

  char xbuf[100];
  if (dns_domain_equal(d,(unsigned char *)"\011localhost\0")) {
    byte_copy(ip,16,"\0\0\0\0\0\0\0\0\0\0\377\377\177\0\0\1");
    return 1;
  }
  if (!dtis(xbuf, sizeof xbuf, d)) return 0;
  return strtoip4(ip, xbuf);
}

static int globalip6(unsigned char *d,unsigned char ip[16]) {
  char xbuf[100];
  if (dns_domain_equal(d,(unsigned char *)"\011localhost\0")) {
    byte_copy(ip,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1");
    return 1;
  }
  if (!dtis(xbuf, sizeof xbuf, d)) return 0;
  return strtoip6(ip, xbuf);
}


static int findkey(const unsigned char *dn,unsigned char key[32])
{
  unsigned char c;

  while (c = *dn++) {
    if (c == 54)
      if (!case_diffb(dn,3,"uz5"))
        if (base32_decode(key,dn + 3,51,1) == 32)
          return 1;
    dn += (unsigned int) c;
  }

  return 0;
}

static unsigned char *t1 = 0;
static unsigned char *t2 = 0;
static unsigned char *t3 = 0;
static unsigned char *cname = 0;
static unsigned char *referral = 0;
static long long *records = 0;

static int smaller(unsigned char *buf,long long len,long long pos1,long long pos2)
{
  unsigned char header1[12];
  unsigned char header2[12];
  int r;
  long long len1;
  long long len2;

  pos1 = dns_packet_getname(buf,len,pos1,&t1);
  dns_packet_copy(buf,len,pos1,header1,10);
  pos2 = dns_packet_getname(buf,len,pos2,&t2);
  dns_packet_copy(buf,len,pos2,header2,10);

  r = byte_diff(header1,4,header2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  len1 = dns_domain_length(t1);
  len2 = dns_domain_length(t2);
  if (len1 < len2) return 1;
  if (len1 > len2) return 0;

  r = case_diffb(t1,len1,t2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  if (pos1 < pos2) return 1;
  return 0;
}

static void addserver(struct query *z,const unsigned char *addr,const unsigned char *key)
{
  int k;
  int i;
  unsigned char *kk;

  if (key) z->flaghavekeys[z->level - 1] = 1;

  for (k = 0;k < 256;k += 16) {
    i = k >> 4;
    if (byte_isequal(z->servers[z->level - 1] + k,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
      byte_copy(z->servers[z->level - 1] + k,16,addr);
      kk = z->keys[z->level - 1] + 33 * i;
      if (key) {
        byte_copy(kk + 1,32,key);
        kk[0] = flagdnscurvetype1;
      }
      else {
        kk[0] = 0;
      }
      break;
    }
  }

  /* add txt */
  if (!key || !flagdnscurvetype2) return;
  for (k = 0;k < 256;k += 16) {
    i = k >> 4;
    kk = z->keys[z->level - 1] + 33 * i;
    if (byte_isequal(z->servers[z->level - 1] + k,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
      byte_copy(z->servers[z->level - 1] + k,16,addr);
      byte_copy(kk + 1,32,key);
      kk[0] = flagdnscurvetype2;
      break;
    }
  }
}

crypto_uint64 tx4 = 0;
crypto_uint64 tx6 = 0;

static int doit(struct query *z,int state)
{
  unsigned char key[259];
  unsigned char *cached;
  long long cachedlen;
  unsigned char *buf;
  long long len;
  unsigned char *whichserver;
  unsigned char *whichkey;
  unsigned char header[16];
  unsigned char misc[20];
  unsigned char pubkey[32];
  int flaghaskey;
  long long rcode;
  long long posanswers;
  crypto_uint16 numanswers;
  long long posauthority;
  crypto_uint16 numauthority;
  /* long long posglue; */
  crypto_uint16 numglue;
  long long pos;
  long long pos2;
  crypto_uint16 datalen;
  unsigned char *control;
  unsigned char *d;
  const unsigned char *dtype;
  long long dlen;
  int flagout;
  int flagcname;
  int flagreferral;
  unsigned char flagns;
  int flagsoa;
  long long ttl;
  long long soattl;
  long long cnamettl;
  long long cachedttl;
  unsigned char cachedflag;
  long long i;
  long long j;
  long long k;
  long long p;
  long long q;
  int flaghavekeys;

  errno = EIO;
  if (state == 1) goto HAVEPACKET;
  if (state == -1) {
    cachegeneric2(DNS_T_AXFR, z->type, z->name[z->level], (unsigned char *)"", 0, 10, 0);
    log_servfail(z->name[z->level]);
    goto SERVFAIL;
  }


  NEWNAME:
  if (++z->loop == QUERY_MAXLOOP) goto DIE;
  d = z->name[z->level];
  /* dtype = z->level ? DNS_T_A : z->type; */
  dtype = z->level ? (z->ipv6[z->level] ? DNS_T_AAAA : DNS_T_A) : z->type;
  dlen = dns_domain_length(d);

  if (globalip(d,misc) && typematch(DNS_T_A,dtype)) {
    if (z->level) {
      addserver(z,misc,0);
      goto LOWERLEVEL;
    }
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_A,dtype)) {
      if (!response_rstart(d,DNS_T_A,655360)) goto DIE;
      if (!response_addbytes(misc + 12,4)) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    return 1;
  }

  if (globalip6(d,misc) && typematch(DNS_T_AAAA,dtype)) {
    if (z->level) {
      addserver(z,misc,0);
      goto LOWERLEVEL;
    }
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_AAAA,dtype)) {
      if (!response_rstart(d,DNS_T_AAAA,655360)) goto DIE;
      if (!response_addbytes(misc,16)) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    return 1;
  }

  if (dns_domain_equal(d,(unsigned char *)"\0011\0010\0010\003127\7in-addr\4arpa\0")) {
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) goto DIE;
    if (typematch(DNS_T_PTR,dtype)) {
      if (!response_rstart(d,DNS_T_PTR,655360)) goto DIE;
      if (!response_addname((unsigned char *)"\011localhost\0")) goto DIE;
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    log_stats();
    return 1;
  }

  if (dlen <= 255) {
    byte_copy(key,2,DNS_T_ANY);
    byte_copy(key + 2,dlen,d);
    case_lowerb(key + 2,dlen);
    cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
    if (cached) {
      log_cachednxdomain(d);
      goto NXDOMAIN;
    }

    byte_copy(key,2,DNS_T_AXFR);
    byte_copy(key + 2 + dlen,2,dtype);
    cached = cache_get(key,dlen + 4,&cachedlen,&ttl,0);
    if (cached && cachedlen == 0) {
      log_cachedservfail(d, dtype);
      goto SERVFAIL;
    }

    byte_copy(key,2,DNS_T_CNAME);
    cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
    if (cached) {
      if (typematch(DNS_T_CNAME,dtype)) {
        log_cachedanswer(d,DNS_T_CNAME);
        if (!rqa(z)) goto DIE;
	if (!response_cname(z->name[0],cached,ttl)) goto DIE;
	cleanup(z);
	return 1;
      }
      log_cachedcname(d,cached);
      if (!dns_domain_copy(&cname,cached)) goto DIE;
      goto CNAME;
    }

    if (typematch(DNS_T_NS,dtype)) {
      byte_copy(key,2,DNS_T_NS);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
      if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_NS);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while (pos = dns_packet_getname(cached,cachedlen,pos,&t2)) {
	  if (!response_rstart(d,DNS_T_NS,ttl)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_PTR,dtype)) {
      byte_copy(key,2,DNS_T_PTR);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
      if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_PTR);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while (pos = dns_packet_getname(cached,cachedlen,pos,&t2)) {
	  if (!response_rstart(d,DNS_T_PTR,ttl)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_MX,dtype)) {
      byte_copy(key,2,DNS_T_MX);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
      if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,DNS_T_MX);
	if (!rqa(z)) goto DIE;
	pos = 0;
	while (pos = dns_packet_copy(cached,cachedlen,pos,misc,2)) {
	  pos = dns_packet_getname(cached,cachedlen,pos,&t2);
	  if (!pos) break;
	  if (!response_rstart(d,DNS_T_MX,ttl)) goto DIE;
	  if (!response_addbytes(misc,2)) goto DIE;
	  if (!response_addname(t2)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_SOA,dtype)) {
      byte_copy(key,2,DNS_T_SOA);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
        log_cachedanswer(d,DNS_T_SOA);
        if (!rqa(z)) goto DIE;
        pos = 0;
        while (pos = dns_packet_copy(cached,cachedlen,pos,misc,20)) {
          pos = dns_packet_getname(cached,cachedlen,pos,&t2);
          if (!pos) break;
          pos = dns_packet_getname(cached,cachedlen,pos,&t3);
          if (!pos) break;
          if (!response_rstart(d,DNS_T_SOA,ttl)) goto DIE;
          if (!response_addname(t2)) goto DIE;
          if (!response_addname(t3)) goto DIE;
          if (!response_addbytes(misc,20)) goto DIE;
          response_rfinish(RESPONSE_ANSWER);
        }
        cleanup(z);
        return 1;
      }
    }


    if (typematch(DNS_T_A,dtype)) {
      byte_copy(key,2,DNS_T_A);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,&flagns);
      if (cached && !cachedlen && z->level) { /* if we were looking the A record up to find an NS, try IPv6 too */
        z->ipv6[z->level]=1;
        goto NEWNAME;
      }
      if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
	if (z->level) {
          flaghaskey = findkey(d,pubkey);
	  log_cachedanswer(d,DNS_T_A);
	  while (cachedlen >= 4) {
            byte_copy(misc, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
            byte_copy(misc + 12, 4, cached);
            addserver(z,misc,flaghaskey ? pubkey : 0);
	    cached += 4;
	    cachedlen -= 4;
	  }
          /* if we were looking the A record up to find an NS, try IPv6 too */
          byte_copy(key,2,DNS_T_AAAA);
          cached = cache_get(key,dlen + 2,&cachedlen,&ttl,&flagns);
          if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
              flaghaskey = findkey(d,pubkey);
              log_cachedanswer(d,DNS_T_AAAA);
              while (cachedlen >= 16) {
                addserver(z,cached,flaghaskey ? pubkey : 0);
	        cached += 16;
	        cachedlen -= 16;
              }
          }
	  goto LOWERLEVEL;
	}

	log_cachedanswer(d,DNS_T_A);
	if (!rqa(z)) goto DIE;
	while (cachedlen >= 4) {
	  if (!response_rstart(d,DNS_T_A,ttl)) goto DIE;
	  if (!response_addbytes(cached,4)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	  cached += 4;
	  cachedlen -= 4;
	}
        if (!flagns){
          cleanup(z);
          return 1;
        }
        byte_copy(key,2,DNS_T_NS);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
        if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
          pos = 0;
          while (pos = dns_packet_getname(cached,cachedlen,pos,&t2)) {
            if (!response_rstart(d,DNS_T_NS,ttl)) goto DIE;
            if (!response_addname(t2)) goto DIE;
            response_rfinish(RESPONSE_AUTHORITY);
          }
          cleanup(z);
          return 1;
        }
      }
    }

    if (typematch(DNS_T_AAAA,dtype)) {
      byte_copy(key,2,DNS_T_AAAA);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,&flagns);
      if (cached && !cachedlen && z->level) { /* if we were looking the AAAA record up to find an NS, go to LOWERLEVEL */
        goto LOWERLEVEL;
      }
      if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
        if (z->level) {
          flaghaskey = findkey(d,pubkey);
          log_cachedanswer(d,DNS_T_AAAA);
          while (cachedlen >= 16) {
            byte_copy(misc, 16, cached);
            addserver(z,misc,flaghaskey ? pubkey : 0);
            cached += 16;
            cachedlen -= 16;
          }
          goto LOWERLEVEL;
        }

        log_cachedanswer(d,DNS_T_AAAA);
        if (!rqa(z)) goto DIE;
        while (cachedlen >= 16) {
          if (!response_rstart(d,DNS_T_AAAA,ttl)) goto DIE;
          if (!response_addbytes(cached,16)) goto DIE;
          response_rfinish(RESPONSE_ANSWER);
          cached += 16;
          cachedlen -= 16;
        }
        if (!flagns){
          cleanup(z);
          return 1;
        }
        byte_copy(key,2,DNS_T_NS);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
        if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
          pos = 0;
          while (pos = dns_packet_getname(cached,cachedlen,pos,&t2)) {
            if (!response_rstart(d,DNS_T_NS,ttl)) goto DIE;
            if (!response_addname(t2)) goto DIE;
            response_rfinish(RESPONSE_AUTHORITY);
          }
          cleanup(z);
          return 1;
        }
      }
    }

    if (!typematch(DNS_T_ANY,dtype) && !typematch(DNS_T_AXFR,dtype) && !typematch(DNS_T_CNAME,dtype) && !typematch(DNS_T_NS,dtype) && !typematch(DNS_T_PTR,dtype) && !typematch(DNS_T_A,dtype) && !typematch(DNS_T_MX,dtype) && !typematch(DNS_T_AAAA,dtype) && !typematch(DNS_T_SOA,dtype)) {
      byte_copy(key,2,dtype);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl,&flagns);
      if (cached && (cachedlen || !byte_isequal(dtype,2,DNS_T_ANY))) {
	log_cachedanswer(d,dtype);
	if (!rqa(z)) goto DIE;
	while (cachedlen >= 2) {
	  datalen = uint16_unpack_big(cached);
	  cached += 2;
	  cachedlen -= 2;
	  if (datalen > cachedlen) goto DIE;
	  if (!response_rstart(d,dtype,ttl)) goto DIE;
	  if (!response_addbytes(cached,datalen)) goto DIE;
	  response_rfinish(RESPONSE_ANSWER);
	  cached += datalen;
	  cachedlen -= datalen;
	}
        cleanup(z);
        return 1;
      }
    }
  }


  for (;;) {
    if (roots(z->servers[z->level],z->keys[z->level],&flaghavekeys,d)) {
      z->flaghavekeys[z->level] = flaghavekeys;
      for (j = 0;j < QUERY_MAXNS;++j)
        dns_domain_free(&z->ns[z->level][j]);
      z->control[z->level] = d;
      break;
    }

    if (!flagforwardonly && (z->level < 2))
      if (dlen < 255) {
        byte_copy(key,2,DNS_T_NS);
        byte_copy(key + 2,dlen,d);
        case_lowerb(key + 2,dlen);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl,0);
        if (cached && cachedlen) {
	  z->control[z->level] = d;
          byte_zero(z->servers[z->level],256);
          byte_zero(z->keys[z->level],528);
          z->flaghavekeys[z->level] = 0;
          for (j = 0;j < QUERY_MAXNS;++j)
            dns_domain_free(&z->ns[z->level][j]);
          pos = 0;
          j = 0;
          while (pos = dns_packet_getname(cached,cachedlen,pos,&t1)) {
	    log_cachedns(d,t1);
            if (j < QUERY_MAXNS)
              if (!dns_domain_copy(&z->ns[z->level][j++],t1)) goto DIE;
	  }
          break;
        }
      }

    if (!*d) goto DIE;
    j = 1 + (unsigned int) (unsigned char) *d;
    dlen -= j;
    d += j;
  }


  HAVENS:
  for (j = 0;j < QUERY_MAXNS;++j)
    if (z->ns[z->level][j]) {
      if (z->level + 1 < QUERY_MAXLEVEL) {
        if (!dns_domain_copy(&z->name[z->level + 1],z->ns[z->level][j])) goto DIE;
        dns_domain_free(&z->ns[z->level][j]);
        ++z->level;
        z->ipv6[z->level]=0;
        goto NEWNAME;
      }
      dns_domain_free(&z->ns[z->level][j]);
    }


  for (j = 0;j < 256;j += 16)
    if (!byte_isequal(z->servers[z->level] + j,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
      break;
  if (j == 256) { log_servfail(z->name[z->level]); goto SERVFAIL; }


  byte_copy(key,2,DNS_T_AXFR);
  for (j = 0;j < 256;j += 16) {
    k = j >> 4;
    if (!byte_isequal(z->servers[z->level] + j,16,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
      whichkey = z->keys[z->level] + 33 * k;
      if (whichkey[0]) {
        byte_copy(key + 2,32,whichkey + 1);
        cached = cache_get(key,34,&cachedlen,&ttl,0);
        if (cached && (cachedlen == 32)) {
          byte_copy(whichkey + 1,32,cached);
          continue;
        }
        crypto_box_curve25519xsalsa20poly1305_beforenm((unsigned char *) whichkey + 1,(const unsigned char *) whichkey + 1,(const unsigned char *) secretkey);
        cache_set(key,34,whichkey + 1,32,655360,0);
      }
    }
  }

  dns_sortipkey(z->servers[z->level],z->keys[z->level],256);
  /* dtype = z->level ? DNS_T_A : z->type; */
  dtype = z->level ? (z->ipv6[z->level] ? DNS_T_AAAA : DNS_T_A) : z->type;
  log_tx(z->name[z->level],dtype,z->control[z->level],z->servers[z->level],z->keys[z->level],z->flaghavekeys[z->level],z->level);
  if (dns_transmit_startext(&z->dt,z->servers[z->level],flagforwardonly,flagtcponly,flagipv4only,z->name[z->level],dtype,z->localip,remoteport,z->keys[z->level],publickey,z->control[z->level]) == -1) goto DIE;
  return 0;


  LOWERLEVEL:
  dns_domain_free(&z->name[z->level]);
  for (j = 0;j < QUERY_MAXNS;++j)
    dns_domain_free(&z->ns[z->level][j]);
  --z->level;
  goto HAVENS;


  HAVEPACKET:
  if (++z->loop == QUERY_MAXLOOP) goto DIE;
  buf = z->dt.packet;
  len = z->dt.packetlen;

  whichserver = (unsigned char *)z->dt.servers + 16 * z->dt.curserver;
  whichkey = (unsigned char *)z->dt.keys + 33 * z->dt.curserver;
  if (xsocket_type(whichserver) == XSOCKET_V4) ++tx4;
  if (xsocket_type(whichserver) == XSOCKET_V6) ++tx6;
  control = z->control[z->level];
  d = z->name[z->level];
  /* dtype = z->level ? DNS_T_A : z->type; */
  dtype = z->level ? (z->ipv6[z->level] ? DNS_T_AAAA : DNS_T_A) : z->type;

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) goto DIE;
  pos = dns_packet_skipname(buf,len,pos); if (!pos) goto DIE;
  pos += 4;
  posanswers = pos;

  numanswers = uint16_unpack_big(header + 6);
  numauthority = uint16_unpack_big(header + 8);
  numglue = uint16_unpack_big(header + 10);

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) goto DIE; /* impossible; see irrelevant() */

  flagout = 0;
  flagcname = 0;
  flagreferral = 0;
  flagns = 0;
  flagsoa = 0;
  soattl = 0;
  cnamettl = 0;
  for (j = 0;j < numanswers;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;

    if (dns_domain_equal(t1,d))
      if (byte_isequal(header + 2,2,DNS_C_IN)) { /* should always be true */
        if (byte_isequal(dtype,2,DNS_T_ANY))
          if (byte_isequal(header,2,DNS_T_NS))
            flagns = 1;
        if (typematch(header,dtype))
          flagout = 1;
        else if (typematch(header,DNS_T_CNAME)) {
          if (!dns_packet_getname(buf,len,pos,&cname)) goto DIE;
          flagcname = 1;
	  cnamettl = ttlget(header + 4);
        }
      }
  
    datalen=uint16_unpack_big(header + 8);
    pos += datalen;
  }
  posauthority = pos;

  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;

    if (typematch(header,DNS_T_SOA)) {
      flagsoa = 1;
      soattl = ttlget(header + 4);
      if (soattl > 3600) soattl = 3600;
    }
    else if (typematch(header,DNS_T_NS)) {
      flagreferral = 1;
      if (dns_domain_equal(t1,d)) flagns = 1;
      if (!dns_domain_copy(&referral,t1)) goto DIE;
    }

    datalen=uint16_unpack_big(header + 8);
    pos += datalen;
  }
  /* posglue = pos; */


  if (!flagcname && !rcode && !flagout && flagreferral && !flagsoa)
    if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
      log_lame(whichserver,control,referral);
      byte_zero(whichserver,16);
      goto HAVENS;
    }


  if (records) { alloc_free(records); records = 0; }

  k = numanswers + numauthority + numglue;
  records = (long long *) alloc(k * sizeof(long long));
  if (!records) goto DIE;

  pos = posanswers;
  for (j = 0;j < k;++j) {
    records[j] = pos;
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    datalen=uint16_unpack_big(header + 8);
    pos += datalen;
  }

  i = j = k;
  while (j > 1) {
    if (i > 1) { --i; pos = records[i - 1]; }
    else { pos = records[j - 1]; records[j - 1] = records[i - 1]; --j; }

    q = i;
    while ((p = q * 2) < j) {
      if (!smaller(buf,len,records[p],records[p - 1])) ++p;
      records[q - 1] = records[p - 1]; q = p;
    }
    if (p == j) {
      records[q - 1] = records[p - 1]; q = p;
    }
    while ((q > i) && smaller(buf,len,records[(p = q/2) - 1],pos)) {
      records[q - 1] = records[p - 1]; q = p;
    }
    records[q - 1] = pos;
  }

  i = 0;
  while (i < k) {
    unsigned char type[2];

    pos = dns_packet_getname(buf,len,records[i],&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    ttl = ttlget(header + 4);

    byte_copy(type,2,header);
    if (!byte_isequal(header + 2,2,DNS_C_IN)) { ++i; continue; }

    for (j = i + 1;j < k;++j) {
      pos = dns_packet_getname(buf,len,records[j],&t2); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
      if (!dns_domain_equal(t1,t2)) break;
      if (!byte_isequal(header,2,type)) break;
      if (!byte_isequal(header + 2,2,DNS_C_IN)) break;
    }

    if (!dns_domain_suffix(t1,control)) { i = j; continue; }
    if (!roots_same(t1,control)) { i = j; continue; }

    if (byte_isequal(type,2,DNS_T_ANY))
      ;
    else if (byte_isequal(type,2,DNS_T_AXFR))
      ;
    else if (byte_isequal(type,2,DNS_T_SOA)) {
      int non_authority = 0;
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos,&t3); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,misc,20); if (!pos) goto DIE;
        if (records[i] < posauthority) {
          log_rrsoa(whichserver,t1,t2,t3,misc,ttl,whichkey[0]);
          save_data(misc,20);
          save_data(t2,dns_domain_length(t2));
          save_data(t3,dns_domain_length(t3));
          non_authority++;
        }
        ++i;
      }
      if (non_authority)
        save_finish(DNS_T_SOA,t1,ttl,0);
    }
    else if (byte_isequal(type,2,DNS_T_CNAME)) {
      pos = dns_packet_skipname(buf,len,records[j - 1]); if (!pos) goto DIE;
      pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
      log_rrcname(whichserver,t1,t2,ttl,whichkey[0]);
      cachegeneric(DNS_T_CNAME,t1,t2,dns_domain_length(t2),ttl,0);
    }
    else if (byte_isequal(type,2,DNS_T_PTR)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
        log_rrptr(whichserver,t1,t2,ttl,whichkey[0]);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_PTR,t1,ttl,0);
    }
    else if (byte_isequal(type,2,DNS_T_NS)) {
      cachedflag = 0;
      if (posauthority <= records[i]) {
        dlen = dns_domain_length(t1);
        byte_copy(key,2,DNS_T_NS);
        byte_copy(key + 2,dlen,t1);
        case_lowerb(key + 2,dlen);
        if (dns_domain_equal(t1,control)) {
          if (cache_get(key,dlen + 2,&cachedlen,&cachedttl,&cachedflag)) {
            if (cachedflag) if (cachedttl < ttl) ttl = cachedttl;
          }
        }
      }
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) goto DIE;
        log_rrns(whichserver,t1,t2,ttl,whichkey[0]);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_NS,t1,ttl,dns_domain_equal(t1,control));
    }
    else if (byte_isequal(type,2,DNS_T_MX)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos + 10,misc,2); if (!pos) goto DIE;
        pos = dns_packet_getname(buf,len,pos,&t2); if (!pos) goto DIE;
        log_rrmx(whichserver,t1,t2,misc,ttl,whichkey[0]);
        save_data(misc,2);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_MX,t1,ttl,0);
    }
    else if (byte_isequal(type,2,DNS_T_A)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        if (byte_isequal(header + 8,2,"\0\4")) {
          pos = dns_packet_copy(buf,len,pos,header,4); if (!pos) goto DIE;
          save_data(header,4);
          log_rra(whichserver,t1,header,ttl,whichkey[0]);
        }
        ++i;
      }
      save_finish(DNS_T_A,t1,ttl,flagns);
    }
    else if (byte_isequal(type,2,DNS_T_AAAA)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        if (uint16_unpack_big(header + 8) == 16) {
          pos = dns_packet_copy(buf,len,pos,header,16); if (!pos) goto DIE;
          save_data(header,16);
          log_rraaaa(whichserver,t1,header,ttl,whichkey[0]);
        }
        ++i;
      }
      save_finish(DNS_T_AAAA,t1,ttl,flagns);
    }
    else {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        datalen=uint16_unpack_big(header + 8);
        if (datalen > len - pos) goto DIE;
        save_data(header + 8,2);
        save_data(buf + pos,datalen);
        log_rr(whichserver,t1,type,buf + pos,datalen,ttl,whichkey[0]);
        ++i;
      }
      save_finish(type,t1,ttl,0);
    }

    i = j;
  }

  alloc_free(records); records = 0;

  if (flagcname) {
    ttl = cnamettl;
    CNAME:
    if (!z->level) {
      if (z->alias[QUERY_MAXALIAS - 1]) goto DIE;
      for (j = QUERY_MAXALIAS - 1;j > 0;--j)
        z->alias[j] = z->alias[j - 1];
      for (j = QUERY_MAXALIAS - 1;j > 0;--j)
        z->aliasttl[j] = z->aliasttl[j - 1];
      z->alias[0] = z->name[0];
      z->aliasttl[0] = ttl;
      z->name[0] = 0;
    }
    if (!dns_domain_copy(&z->name[z->level],cname)) goto DIE;
    goto NEWNAME;
  }

  if (rcode == 3) {
    log_nxdomain(whichserver,d,soattl);
    cachegeneric(DNS_T_ANY,d,(unsigned char *)"",0,soattl,0);

    NXDOMAIN:
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) goto DIE;
    response_nxdomain();
    cleanup(z);
    return 1;
  }

  if (!flagout && flagsoa)
    if (!byte_isequal(DNS_T_ANY,2,dtype))
      if (!byte_isequal(DNS_T_AXFR,2,dtype))
        if (!byte_isequal(DNS_T_CNAME,2,dtype)) {
          save_start();
          save_finish(dtype,d,soattl,0);
	  log_nodata(whichserver,d,dtype,soattl);
          if (z->level && byte_isequal(DNS_T_A,2,dtype)) {
            d = z->name[z->level];
            z->ipv6[z->level] = 1;
            goto NEWNAME; /* retry, will ask for AAAA next */
          }
        }

  log_stats();

  if (flagout || flagsoa || !flagreferral) {
    if (z->level) {
      flaghaskey = findkey(d,pubkey);
      pos = posanswers;
      for (j = 0;j < numanswers;++j) {
        pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
        datalen=uint16_unpack_big(header + 8);
        if (dns_domain_equal(t1,d)) {
          if (typematch(header,DNS_T_A))
            if (byte_isequal(header + 2,2,DNS_C_IN)) /* should always be true */
              if (datalen == 4) {
                byte_copy(misc, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
                if (!dns_packet_copy(buf,len,pos,misc+12,4)) goto DIE;
                addserver(z,misc,flaghaskey ? pubkey : 0);
              }
          if (typematch(header,DNS_T_AAAA))
            if (byte_isequal(header + 2,2,DNS_C_IN)) /* should always be true */
              if (datalen == 16) {
                if (!dns_packet_copy(buf,len,pos,misc,16)) goto DIE;
                addserver(z,misc,flaghaskey ? pubkey : 0);
              }
        }
        pos += datalen;
      }
      goto LOWERLEVEL;
    }


    if (!rqa(z)) goto DIE;

    pos = posanswers;
    for (j = 0;j < numanswers;++j) {
      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
      ttl = ttlget(header + 4);
      datalen=uint16_unpack_big(header + 8);
      if (dns_domain_equal(t1,d))
        if (byte_isequal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (typematch(header,dtype)) {
            if (!response_rstart(t1,header,ttl)) goto DIE;
  
            if (typematch(header,DNS_T_NS) || typematch(header,DNS_T_CNAME) || typematch(header,DNS_T_PTR)) {
              if (!dns_packet_getname(buf,len,pos,&t2)) goto DIE;
              if (!response_addname(t2)) goto DIE;
            }
            else if (typematch(header,DNS_T_MX)) {
              pos2 = dns_packet_copy(buf,len,pos,misc,2); if (!pos2) goto DIE;
              if (!response_addbytes(misc,2)) goto DIE;
              if (!dns_packet_getname(buf,len,pos2,&t2)) goto DIE;
              if (!response_addname(t2)) goto DIE;
            }
            else if (typematch(header,DNS_T_SOA)) {
              pos2 = dns_packet_getname(buf,len,pos,&t2); if (!pos2) goto DIE;
              if (!response_addname(t2)) goto DIE;
              pos2 = dns_packet_getname(buf,len,pos2,&t3); if (!pos2) goto DIE;
              if (!response_addname(t3)) goto DIE;
              pos2 = dns_packet_copy(buf,len,pos2,misc,20); if (!pos2) goto DIE;
              if (!response_addbytes(misc,20)) goto DIE;
            }
            else {
              if (pos + datalen > len) goto DIE;
              if (!response_addbytes(buf + pos,datalen)) goto DIE;
            }
  
            response_rfinish(RESPONSE_ANSWER);
          }
      pos += datalen;
    }

    pos = posauthority;
    for (j = 0;j < numauthority;++j) {
      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
      ttl = ttlget(header + 4);
      datalen = uint16_unpack_big(header + 8);
      if (dns_domain_equal(t1,d))
        if (byte_isequal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (typematch(header,DNS_T_NS)) {
            if (!response_rstart(t1,header,ttl)) goto DIE;
            if (!dns_packet_getname(buf,len,pos,&t2)) goto DIE;
            if (!response_addname(t2)) goto DIE;
            response_rfinish(RESPONSE_AUTHORITY);
          }
      pos += datalen;
    }


    cleanup(z);
    return 1;
  }

  if (!dns_domain_suffix(d,referral)) goto DIE;

  /* In strict "forwardonly" mode, we don't, as the manual states,
  ** contact a chain of servers according to "NS" resource records.
  ** We don't obey any referral responses, therefore.  Instead, we
  ** eliminate the server from the list and try the next one.
  */
  if (flagforwardonly) {
      log_ignore_referral(whichserver,control,referral);
      byte_zero(whichserver,16);
      goto HAVENS;
  }

  control = d + dns_domain_suffixpos(d,referral);
  z->control[z->level] = control;
  byte_zero(z->servers[z->level],256);
  z->flaghavekeys[z->level] = 0;
  for (j = 0;j < QUERY_MAXNS;++j)
    dns_domain_free(&z->ns[z->level][j]);
  k = 0;

  pos = posauthority;
  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    datalen = uint16_unpack_big(header + 8);
    if (dns_domain_equal(referral,t1)) /* should always be true */
      if (typematch(header,DNS_T_NS)) /* should always be true */
        if (byte_isequal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (k < QUERY_MAXNS)
            if (!dns_packet_getname(buf,len,pos,&z->ns[z->level][k++])) goto DIE;
    pos += datalen;
  }


  goto HAVENS;


  SERVFAIL:
  if (z->level) goto LOWERLEVEL;
  if (!rqa(z)) goto DIE;
  response_servfail();
  cleanup(z);
  return 1;


  DIE:
  cleanup(z);
  if (records) { alloc_free(records); records = 0; }
  return -1;
}

int query_start(struct query *z,unsigned char *dn,unsigned char type[2],unsigned char class[2],unsigned char localip[32])
{
  if (byte_isequal(type,2,DNS_T_AXFR)) { errno = EPERM; return -1; }

  cleanup(z);
  z->level = 0;
  z->loop = 0;

  if (!dns_domain_copy(&z->name[0],dn)) return -1;
  byte_copy(z->type,2,type);
  byte_copy(z->class,2,class);
  byte_copy(z->localip,32,localip);
  z->ipv6[0]=0;

  return doit(z,0);
}

int query_get(struct query *z,struct pollfd *x,long long stamp)
{
  switch(dns_transmit_get(&z->dt,x,stamp)) {
    case 1:
      return doit(z,1);
    case -1:
      return doit(z,-1);
  }
  return 0;
}

void query_io(struct query *z,struct pollfd *x,long long *deadline)
{
  dns_transmit_io(&z->dt,x,deadline);
}
