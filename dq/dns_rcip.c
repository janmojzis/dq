#include "milliseconds.h"
#include "openreadclose.h"
#include "byte.h"
#include "env.h"
#include "stralloc.h"
#include "strtoip.h"
#include "strtomultiip.h"
#include "hasipv6.h"
#include "xsocket.h"
#include "dns.h"

static stralloc data = {0};

static int init(unsigned char ip[256]) {

    long long i, j, iplen = 0;
    long long k = 0;

    byte_zero(ip, 256);

    iplen = strtomultiip(ip, 256, env_get("DNSCACHEIP"));

    if (!iplen) {
        i = openreadclose("/etc/resolv.conf", &data, 64);
        if (i == -1) return -1;
        if (i) {
            if (!stralloc_append(&data, "\n")) return -1;
            i = 0;
            for (j = 0; j < data.len; ++j) {
                if (data.s[j] == '\n') {
                    k = j;
                    while (k >= 0 && ((data.s[k] == ' ') || (data.s[k] == '\t') || (data.s[k] == '\n'))) {
                        data.s[k--] = 0;
                    }
                    if (byte_isequal("nameserver ", 11, data.s + i) || byte_isequal("nameserver\t", 11, data.s + i)) {
                        i += 10;
                        while ((data.s[i] == ' ') || (data.s[i] == '\t'))
                            ++i;
                        if (iplen + 16 <= 256) {
                            if (strtoip(ip + iplen, (char *)data.s + i)) {
                                if (byte_isequal(ip + iplen, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) {
                                    byte_copy(ip + iplen, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1");
                                }
                                if (byte_isequal(ip + iplen, 16, "\0\0\0\0\0\0\0\0\0\0\377\377\0\0\0\0")) {
                                    byte_copy(ip + iplen, 16, "\0\0\0\0\0\0\0\0\0\0\377\377\177\0\0\1");
                                }
                                iplen += 16;
	                    }
                        }
                    }
                    i = j + 1;
                }
            }
        }
    }

    if (!iplen) {
#ifdef HASIPV6
        byte_copy(ip + iplen, 16, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1");
        iplen += 16;
#endif
        byte_copy(ip + iplen, 16, "\0\0\0\0\0\0\0\0\0\0\377\377\177\0\0\1");
        iplen += 16;
    }
    return 0;
}

static int ok = 0;
static long long uses = 0;
static long long deadline = 0;
static unsigned char ip[256]; /* defined if ok */

int dns_resolvconfip(unsigned char *s) {

    long long now;

    now = milliseconds();
    if (deadline < now) ok = 0;
    if (uses <= 0) ok = 0;

    if (!ok) {
        if (init(ip) == -1) return -1;
        deadline = 600000 + now;
        uses = 10000;
        ok = 1;
    }

    --uses;
    byte_copy(s, sizeof ip, ip);
    return 0;
}
