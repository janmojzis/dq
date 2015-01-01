#include "crypto_uint16.h"
#include "porttostr.h"

char *porttostr(char *strnum, const unsigned char *port) {

    crypto_uint16 num;
    static char staticbuf[PORTTOSTR_LEN];

    if (!strnum) strnum = staticbuf; /* not thread-safe */

    num = port[0];
    num <<= 8;
    num |= port[1];

    return numtostr(strnum, num);
}
