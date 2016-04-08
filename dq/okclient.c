#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "byte.h"
#include "iptostr.h"
#include "okclient.h"

static char fn[3 + IPTOSTR_LEN];

int okclient(unsigned char *ip) {

    struct stat st;
    long long i;
    char sep;

    fn[0] = 'i';
    fn[1] = 'p';
    fn[2] = '/';
    iptostrx(fn + 3, ip);

    if (!byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) {
        sep = ':';
    }
    else {
        sep = '.';
    }

    for (;;) {
        if (stat(fn, &st) == 0) return 1;
        /* treat temporary error as rejection */
        i = str_rchr(fn, sep);
        if (!fn[i]) return 0;
        fn[i] = 0;
    }
    return 0;
}

