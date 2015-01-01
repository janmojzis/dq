#include "byte.h"
#include "okclient.h"

int okclient(unsigned char *ip) {
    
    /* allow ::1/128 */
    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16, ip)) return 1;

    /* allow 127.0.0.0/8 */
    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377\177", 13, ip)) return 1;

    return 0;
}
