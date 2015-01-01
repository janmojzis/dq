/*
20130605
Jan Mojzis
Public domain.
*/

#include "numtostr.h"

char *numtostr(char *strnum, long long n) {

    int flagsign = 0;
    unsigned long long num = n;
    static char staticbuf[NUMTOSTR_LEN];

    if (!strnum) strnum = staticbuf; /* not thread-safe */

    if (n < 0) {
        flagsign = 1;
        num = -n;
    }

    strnum += NUMTOSTR_LEN - 1;
    *strnum = 0;

    do {
        *--strnum = '0' + (num % 10);
        num /= 10;
    } while (num);

    if (flagsign) *--strnum = '-';

    return strnum;
}
