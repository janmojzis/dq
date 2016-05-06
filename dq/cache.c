#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include "alloc.h"
#include "byte.h"
#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "uint32_pack.h"
#include "uint32_unpack.h"
#include "seconds.h"
#include "die.h"
#include "randombytes.h"
#include "buffer.h"
#include "open.h"
#include "dns.h"
#include "crypto_auth_siphash24.h"
#include "e.h"
#include "cache.h"

crypto_uint64 cache_motion = 0;
crypto_uint64 cache_hit = 0;
crypto_uint64 cache_miss = 0;

static unsigned char *x = 0;
static crypto_uint32 size;
static crypto_uint32 hsize;
static crypto_uint32 writer;
static crypto_uint32 oldest;
static crypto_uint32 unused;
static unsigned char hashkey[crypto_auth_siphash24_KEYBYTES];

/*
100 <= size <= 3000000000.
4 <= hsize <= size/16.
hsize is a power of 2.

hsize <= writer <= oldest <= unused <= size.
If oldest == unused then unused == size.

x is a hash table with the following structure:
x[0...hsize-1]: hsize/4 head links.
x[hsize...writer-1]: consecutive entries, newest entry on the right.
x[writer...oldest-1]: free space for new entries.
x[oldest...unused-1]: consecutive entries, oldest entry on the left.
x[unused...size-1]: unused.

Each hash bucket is a linked list containing the following items:
the head link, the newest entry, the second-newest entry, etc.
Each link is a 4-byte number giving the xor of
the positions of the adjacent items in the list.

Entries are always inserted immediately after the head and removed at the tail.

Each entry contains the following information:
4-byte link; 4-byte keylen; 4-byte datalen; 8-byte expire time; key; data.
*/

#define MAXKEYLEN 1000
#define MAXDATALEN 1000000

static void cache_impossible(void) {
    die_0(111);
}

static void set4(crypto_uint32 pos, crypto_uint32 u) {
    if (pos > size - 4) cache_impossible();
    uint32_pack(x + pos, u);
}

static crypto_uint32 get4(crypto_uint32 pos) {

    crypto_uint32 result;

    if (pos > size - 4) cache_impossible();
    result = uint32_unpack(x + pos);
    return result;
}

#if 0
static crypto_uint32 hash(const unsigned char *key, crypto_uint32 keylen) {

  unsigned int result = 5381;

  while (keylen) {
    result = (result << 5) + result;
    result ^= (unsigned char) *key;
    ++key;
    --keylen;
  }
  result <<= 2;
  result &= hsize - 4;
  return result;
}
#else
static crypto_uint32 hash(const unsigned char *key, crypto_uint32 keylen) {

    unsigned char a[crypto_auth_siphash24_BYTES];

    crypto_auth_siphash24(a, key, keylen, hashkey);

    return (uint32_unpack(a) & (hsize - 4));
}
#endif

unsigned char *cache_get(const unsigned char *key, long long keylen, long long *datalen, long long *ttl, unsigned char *flags) {

    crypto_uint32 pos;
    crypto_uint32 prevpos;
    crypto_uint32 nextpos;
    crypto_uint32 u;
    long long loop;
    long long xttl;
    unsigned char dummy;
    unsigned char expirestr[8];

    if (!flags) flags = &dummy;

    if (!x) return 0;
    if (keylen > MAXKEYLEN) return 0;

    prevpos = hash(key, keylen);
    pos = get4(prevpos);
    loop = 0;

    *ttl = 0;

    while (pos) {
        if (get4(pos + 4) == keylen) {
            if (pos + 20 + keylen > size) cache_impossible();
            if (byte_isequal(key, keylen, x + pos + 20)) {
                byte_copy(expirestr, 8, x + pos + 12);
                *flags = expirestr[7];
                expirestr[7] = 0;
                xttl = uint64_unpack(expirestr) - seconds();
                if (xttl <= 0) return 0;
                if (xttl > 604800) xttl = 604800;
                *ttl = xttl;

                u = get4(pos + 8);
                if (u > size - pos - 20 - keylen) cache_impossible();
                *datalen = u;

                ++cache_hit;
                return x + pos + 20 + keylen;
            }
        }
        nextpos = prevpos ^ get4(pos);
        prevpos = pos;
        pos = nextpos;
        if (++loop > 100) { ++cache_miss; return 0; } /* to protect against hash flooding */
    }

    ++cache_miss;
    return 0;
}

void cache_set(const unsigned char *key, long long keylen, const unsigned char *data, long long datalen, long long ttl, unsigned char flags) {

    crypto_uint32 entrylen;
    crypto_uint32 keyhash;
    crypto_uint32 pos;

    if (!x) return;
    if (keylen > MAXKEYLEN || keylen < 0) return;
    if (datalen > MAXDATALEN || datalen < 0) return;

    if (ttl <= 0) return;
    if (ttl > 604800) ttl = 604800;

    entrylen = keylen + datalen + 20;

    while (writer + entrylen > oldest) {
        if (oldest == unused) {
            if (writer <= hsize) return;
            unused = writer;
            oldest = hsize;
            writer = hsize;
        }

        pos = get4(oldest);
        set4(pos,get4(pos) ^ oldest);
  
        oldest += get4(oldest + 4) + get4(oldest + 8) + 20;
        if (oldest > unused) cache_impossible();
        if (oldest == unused) {
            unused = size;
            oldest = size;
        }
    }

    keyhash = hash(key, keylen);

    pos = get4(keyhash);
    if (pos)
        set4(pos,get4(pos) ^ keyhash ^ writer);
    set4(writer,pos ^ keyhash);
    set4(writer + 4, keylen);
    set4(writer + 8, datalen);
    uint64_pack(x + writer + 12, seconds() + ttl);
    x[writer + 12 + 7] = flags;
    byte_copy(x + writer + 20, keylen, key);
    byte_copy(x + writer + 20 + keylen, datalen, data);

    set4(keyhash, writer);
    writer += entrylen;
    cache_motion += entrylen;
}

int cache_init(long long cachesize) {

    randombytes(hashkey, sizeof hashkey);

    if (x) {
        alloc_free(x);
        x = 0;
    }

    if (cachesize > 3000000000LL) cachesize = 3000000000LL;
    if (cachesize < 100) cachesize = 100;
    size = cachesize;

    hsize = 4;
    while (hsize <= (size >> 5)) hsize <<= 1;

    x = alloc(size);
    if (!x) return 0;
    byte_zero(x, size);

    writer = hsize;
    oldest = size;
    unused = size;

    return 1;
}

static const char fn[]="dump/dnsdata";
static const char fntmp[]="dump/dnsdata.tmp";

char bspace[8096];
buffer b;

void cache_clean(void) {
    unlink(fn);
    die_0(0);
}

int cache_dump(void) {

    crypto_uint32 pos;
    long long len;
    int r;
    int fd;

    fd = open_trunc(fntmp);
    if (fd == -1) return -1;

    buffer_init(&b, buffer_unixwrite, fd, bspace, sizeof bspace);

    pos = oldest;
    while (pos < unused) {
        len = get4(pos + 4) + get4(pos + 8) + 16;
        if (byte_diff(x + pos + 20, 2, DNS_T_AXFR)){
            if (byte_diff(x + pos + 20, 2, DNS_T_ANY)){
                r = buffer_put(&b, (char *)x + pos + 4, len);
                if (r == -1) { close(fd); return -1; }
            }
        }
        pos += 4 + len;
    }
    pos = hsize;
    while (pos < writer) {
        len = get4(pos + 4) + get4(pos + 8) + 16;
        if (byte_diff(x + pos + 20, 2, DNS_T_AXFR)){
            if (byte_diff(x + pos + 20, 2, DNS_T_ANY)){
                r = buffer_put(&b, (char *)x + pos + 4, len);
                if (r == -1) { close(fd); return -1; }
            }
        }
        pos += 4 + len;
    }
    if (buffer_flush(&b) == -1) { close(fd); return -1; }
    if (fsync(fd) == -1) { close(fd); return -1; }
    if (close(fd) == -1) return -1;
    if (chmod(fntmp, 0600) == -1) return -1;
    if (rename(fntmp,fn) == -1) return -1;
    return 0;
}


int cache_load(void) {

    unsigned char *p, *xx;
    crypto_uint32 pos;
    long long len;
    crypto_uint32 keylen;
    crypto_uint32 datalen;
    int nb;
    struct stat st;
    int fd;
    int flags = 0;
    long long now, expire;
    unsigned char expirestr[8];

    fd = open_read(fn);
    if (fd == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    if (fstat(fd,&st) == -1) { close(fd); return -1; }
    if (st.st_size == 0) { close(fd); return 0; }
    xx = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (xx == MAP_FAILED) {close(fd); return -1;}
    len = st.st_size;
    p   = xx;

    now = seconds();
    pos = 0;
    nb = 0;
    while (pos + 16 <= len) {
        keylen = uint32_unpack(p + pos);
        datalen = uint32_unpack(p + pos + 4);
        byte_copy(expirestr, 8, p + pos + 8);
        flags = expirestr[7];
        expirestr[7] = 0;
        expire = uint64_unpack(expirestr) - now;
        pos += 16;
        if (pos + keylen + datalen > len) break; /* missing data */
        if (expire > 0) {
            cache_set(p + pos, keylen, p + pos + keylen, datalen, expire, flags);
        }
        pos += keylen + datalen;
        nb++;
    }
    munmap(xx, st.st_size);
    close(fd);
    return 0;
}

