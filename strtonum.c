/*
20130605
Jan Mojzis
Public domain.
*/

#include "e.h"
#include "strtonum.h"

/*
The 'strnum(r,buf)' converts 0-terminated string 'buf' into number 'r'.
*/
int strtonum(long long *r, const char *buf) {

    char *bufpos = (char *)buf;
    int flagsign = 0;
    long long i;
    unsigned long long c, ret = 0;

    if (!buf) goto failed;

    switch (buf[0]) {
        case 0:
            goto failed;
            break;
        case '+':
            ++bufpos;
            break;
        case '-':
            flagsign = 1;
            ++bufpos;
            break;
        default:
            break;
    }

    for(i = 0; bufpos[i]; ++i) {
        c = bufpos[i] - '0';
        if (c > 9) break;
        c += 10 * (ret);
        if (ret > c)  goto failed; /* overflow */
        ret = c;
    }
    if (i == 0) goto failed; /* "+..." or "-..." */
    if (flagsign) {
        *r = -ret;
        if (*r > 0) goto failed; /* overflow */
    }
    else {
        *r = ret;
        if (*r < 0) goto failed; /* overflow */
    }
    return 1;

failed:
    *r = 0;
    errno = EINVAL;
    return 0;
}
