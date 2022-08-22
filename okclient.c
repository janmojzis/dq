#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "byte.h"
#include "iptostr.h"
#include "okclient.h"

static char fn[4 + IPTOSTR_LEN];

int okclient(unsigned char *ip) {

    struct stat st;
    long long i;
    char sep;


    /* allow ::1/128 */
    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16, ip)) return 1;
  
    /* allow 127.0.0.0/8 */
    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377\177", 13, ip)) return 1;


    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) {
        fn[0] = 'i';
        fn[1] = 'p';
        fn[2] = '4';
        fn[3] = '/';
        iptostrx(fn + 4, ip);
        sep = '.';
    }
    else {
        fn[0] = 'i';
        fn[1] = 'p';
        fn[2] = '6';
        fn[3] = '/';
        iptostrx(fn + 4, ip);
        sep = ':';
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

