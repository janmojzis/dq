#include <unistd.h>
#include "open.h"
#include "e.h"
#include "str.h"
#include "byte.h"
#include "direntry.h"
#include "strtoip.h"
#include "dns.h"
#include "openreadclose.h"
#include "roots.h"
#include "keyparse.h"

static int flagdnscurvetype1 = 1;
static int flagdnscurvetype2 = 2;

static stralloc data;
static stralloc text;

static long long roots_find(unsigned char *q) {

    long long i,j;

    i = 0;
    while (i < data.len) {
        j = dns_domain_length(data.s + i);
        if (dns_domain_equal(data.s + i, q)) return i + j;
        i += j;
        i += 256 + 528 + 1;
    }
    return -1;
}

static long long roots_search(unsigned char *q) {

    long long r;

    for (;;) {
        r = roots_find(q);
        if (r >= 0) return r;
        if (!*q) return -1; /* user misconfiguration */
        q += *q;
        q += 1;
    }
}

int roots(unsigned char servers[256], unsigned char keys[528], int *flaghavekeys, unsigned char *q) {

    long long r;

    r = roots_find(q);
    if (r == -1) return 0;
    byte_copy(servers, 256, data.s + r);
    byte_copy(keys, 528, data.s + r + 256);
    *flaghavekeys = 0;
    if (data.s[r + 256 + 528]) *flaghavekeys = 1;
    return 1;
}

int roots_same(unsigned char *q, unsigned char *q2) {
    return roots_search(q) == roots_search(q2);
}

static int init2(DIR *dir) {

    direntry *d;
    const char *fqdn;
    static unsigned char *q;
    unsigned char servers[256];
    unsigned char keys[528];
    int flaghavekeys;
    long long serverslen;
    long long keyslen;
    long long i;
    long long j;
    long long k;
    unsigned char *kk;

    byte_zero(keys, 528);

    for (;;) {
        errno = 0;
        d = readdir(dir);
        if (!d) {
            if (errno) return 0;
            return 1;
        }

        if (d->d_name[0] != '.') {
            if (openreadclose(d->d_name, &text, 32) != 1) return 0;
            if (!stralloc_append(&text,"\n")) return 0;

            fqdn = d->d_name;
            if (str_equal(fqdn,"@")) fqdn = ".";
            if (!dns_domain_fromdot(&q,(unsigned char *)fqdn,str_len(fqdn))) return 0;

            serverslen = 0;
            keyslen = 0;
            j = 0;
            k = 0;
            flaghavekeys = 0;
            if (byte_chr(text.s, text.len, '|') != text.len) {
                flaghavekeys = 1;
            }
            for (i = 0;i < text.len;++i) {
	        if (text.s[i] == '|') {
                    k = i + 1;
                    text.s[i] = 0;
                    continue;
                }
	        if (text.s[i] == '\n') {
                    text.s[i] = 0;
	            if (serverslen <= 240) {
	                if (strtoip(servers + serverslen, (char *)text.s + j)) {
                            kk = keys + keyslen;
                            kk[0] = 0;
                            if (k && keyparse(kk + 1, 32, (char *)text.s + k)) {
                                kk[0] = flagdnscurvetype1;
                                serverslen += 16;
	                        keyslen += 33;
                                /* add txt */
	                        if (flagdnscurvetype2 && serverslen <= 240) {
                                    byte_copy(servers + serverslen, 16, servers + serverslen - 16);
                                    byte_copy(keys + keyslen, 33, keys + keyslen - 33);
                                    kk = keys + keyslen;
                                    kk[0] = flagdnscurvetype2;
                                    serverslen += 16;
                                    keyslen += 33;
                                }
                            }
                            else {
                                serverslen += 16;
	                        keyslen += 33;
                            }
                        }
                    }
	            j = i + 1;
                    k = 0;
	        }
            }
            byte_zero(servers + serverslen,256 - serverslen);
            byte_zero(keys + keyslen,528 - keyslen);

            if (!stralloc_catb(&data,q,dns_domain_length(q))) return 0;
            if (!stralloc_catb(&data,servers,256)) return 0;
            if (!stralloc_catb(&data,keys,528)) return 0;
            if (flaghavekeys) {
                if (!stralloc_catb(&data,"1",1)) return 0;
            }
            else {
                if (!stralloc_0(&data)) return 0;
            }
        }
    }
}

static int init1(void) {
    DIR *dir;
    int r;

    if (chdir("servers") == -1) return 0;
    dir = opendir(".");
    if (!dir) return 0;
    r = init2(dir);
    closedir(dir);
    return r;
}

int roots_init(char *x) {

    int fddir;
    int r;

    if (x) {
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

    if (!stralloc_copys(&data, "")) return 0;

    fddir = open_read(".");
    if (fddir == -1) return 0;
    r = init1();
    if (fchdir(fddir) == -1) r = 0;
    close(fddir);
    return r;
}
