/*
20131117
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "e.h"
#include "byte.h"
#include "hasipv6.h"
#include "xsocket.h"

static long long xsocket_send6(int fd, const unsigned char *x, long long xlen, const unsigned char *ip, const unsigned char *port, long long id) {

#ifdef HASIPV6
    struct sockaddr_in6 sa;

    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { errno = EPROTO; return -1; }

    byte_zero(&sa, sizeof sa);
    sa.sin6_family = PF_INET6;
    byte_copy(&sa.sin6_addr, 16, ip);
    byte_copy(&sa.sin6_port, 2, port);
    sa.sin6_scope_id = id;
    return sendto(fd, x, xlen, 0, (struct sockaddr *)&sa, sizeof sa);
#else
    errno = EPROTONOSUPPORT;
    return -1;
#endif

}

static long long xsocket_send4(int fd, const unsigned char *x, long long xlen, const unsigned char *ip, const unsigned char *port, long long id) {

    struct sockaddr_in sa;

    if (!byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { errno = EPROTO; return -1; }

    byte_zero(&sa, sizeof sa);
    sa.sin_family = PF_INET;
    byte_copy(&sa.sin_addr, 4, ip + 12);
    byte_copy(&sa.sin_port, 2, port);
    return sendto(fd, x, xlen, 0, (struct sockaddr *)&sa, sizeof sa);
}

long long xsocket_send(int fd, int type, const unsigned char *x, long long xlen, const unsigned char *ip, const unsigned char *port, long long id) {

    if (xlen < 0 || xlen > 1048576) { errno = EPROTO; return -1; }

    if (type == XSOCKET_V4) {
        return xsocket_send4(fd, x, xlen, ip, port, id);
    }

    if (type == XSOCKET_V6) {
        return xsocket_send6(fd, x, xlen, ip, port, id);
    }
    errno = EPROTO;
    return -1;
}
