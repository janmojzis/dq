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

static int xsocket_bind6(int fd, const unsigned char *ip, const unsigned char *port, long long id) {

#ifdef HASIPV6
    struct sockaddr_in6 sa;

    if (byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { errno = EPROTO; return -1; }

    byte_zero(&sa, sizeof sa);
    sa.sin6_family = PF_INET6;
    byte_copy(&sa.sin6_addr, 16, ip);
    byte_copy(&sa.sin6_port, 2, port);
    sa.sin6_scope_id = id;
    return bind(fd, (struct sockaddr *)&sa, sizeof sa);
#else
    errno = EPROTONOSUPPORT;
    return -1;
#endif

}

static int xsocket_bind4(int fd, const unsigned char *ip, const unsigned char *port, long long id) {

    struct sockaddr_in sa;

    if (!byte_isequal("\0\0\0\0\0\0\0\0\0\0\377\377", 12, ip)) { errno = EPROTO; return -1; }

    byte_zero(&sa, sizeof sa);
    sa.sin_family = PF_INET;
    byte_copy(&sa.sin_addr, 4, ip + 12);
    byte_copy(&sa.sin_port, 2, port);
    return bind(fd, (struct sockaddr *)&sa, sizeof sa);
}

int xsocket_bind(int fd, int type, const unsigned char *ip, const unsigned char *port, long long id) {

    if (type == XSOCKET_V4) {
        return xsocket_bind4(fd, ip, port, id);
    }
    if (type == XSOCKET_V6) {
        return xsocket_bind6(fd, ip, port, id);
    }
    errno = EPROTO;
    return -1;
}

int xsocket_bind_reuse(int fd, int type, const unsigned char *ip, const unsigned char *port, long long id) {

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    return xsocket_bind(fd, type, ip, port, id);
}

void xsocket_tryreservein(int fd, int size) {

    while (size >= 1024) {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size) == 0) return;
        size -= (size >> 5);
    }
}
