#include "byte.h"
#include "xsocket.h"

int xsocket_type(const unsigned char *ip) {

    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) {
        return XSOCKET_V4;
    }
    else {
        return XSOCKET_V6;
    }
}

