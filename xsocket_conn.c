/*
20130505
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "e.h"
#include "byte.h"
#include "hasipv6.h"
#include "xsocket.h"

static int xsocket_connect6(int s, const unsigned char *ip, const unsigned char *port, long long id) {
#ifdef HASIPV6
    struct sockaddr_in6 sa;

    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { errno = EPROTO; return -1; }

    byte_zero(&sa, sizeof sa);
    sa.sin6_family = PF_INET6;
    byte_copy(&sa.sin6_addr, 16, ip);
    byte_copy(&sa.sin6_port, 2, port);
    sa.sin6_scope_id = id;
    return connect(s, (struct sockaddr *)&sa, sizeof sa);
#else
    errno = EPROTONOSUPPORT;
    return -1;
#endif
}

static int xsocket_connect4(int s, const unsigned char *ip, const unsigned char *port, long long id) {

    struct sockaddr_in sa;

    if (!byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { errno = EPROTO; return -1; }

    byte_zero(&sa, sizeof sa);
    sa.sin_family = PF_INET;
    byte_copy(&sa.sin_addr, 4, ip + 12);
    byte_copy(&sa.sin_port, 2, port);
    return connect(s, (struct sockaddr *)&sa, sizeof sa);
}

int xsocket_connect(int s, int type, const unsigned char *ip, const unsigned char *port, long long id) {

    if (type == XSOCKET_V4) {
        return xsocket_connect4(s, ip, port, id);
    }
    if (type == XSOCKET_V6) {
        return xsocket_connect6(s, ip, port, id);
    }
    errno = EPROTO;
    return -1;
}

int xsocket_connected(int s) {

    struct sockaddr sa;
    socklen_t dummy;
    char ch;

    dummy = sizeof sa;
    if (getpeername(s, &sa, &dummy) == -1) {
        if (read(s, &ch, 1) == -1) {}; /* sets errno */
        return 0;
    }
    return 1;
}
