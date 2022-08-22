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

static long long xsocket_recv6(int fd, unsigned char *x, long long xlen, unsigned char *ip, unsigned char *port, long long *id) {

#ifdef HASIPV6
    struct sockaddr_in6 sa;
    socklen_t salen = sizeof sa;
    long long r;

    byte_zero(&sa, sizeof sa);
    r = recvfrom(fd, x, xlen, 0, (struct sockaddr *) &sa, &salen);
    if (r == -1) return -1;
    if (((struct sockaddr *)&sa)->sa_family != PF_INET6) { errno = EPROTO; return -1; }
    if (ip) byte_copy(ip, 16, &sa.sin6_addr);
    if (port) byte_copy(port, 2, &sa.sin6_port);
    if (id) *id = sa.sin6_scope_id;
    return r;
#else
    errno = EPROTONOSUPPORT;
    return -1;
#endif

}

static long long xsocket_recv4(int fd, unsigned char *x, long long xlen, unsigned char *ip, unsigned char *port, long long *id) {

    struct sockaddr_in sa;
    socklen_t salen = sizeof sa;
    long long r;

    byte_zero(&sa, sizeof sa);
    r = recvfrom(fd, x, xlen, 0, (struct sockaddr *) &sa, &salen);
    if (r == -1) return -1;
    if (((struct sockaddr *)&sa)->sa_family != PF_INET) { errno = EPROTO; return -1; }
    if (ip) byte_copy(ip, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
    if (ip) byte_copy(ip + 12, 4, &sa.sin_addr);
    if (port) byte_copy(port, 2, &sa.sin_port);
    if (id) *id = 0;
    return r;
}

long long xsocket_recv(int fd, int type, unsigned char *x, long long xlen, unsigned char *ip, unsigned char *port, long long *id) {

    if (xlen < 0) { errno = EPROTO; return -1; }
    if (xlen > 1048576) xlen = 1048576;

    if (type == XSOCKET_V4) {
        return xsocket_recv4(fd, x, xlen, ip, port, id);
    }
    if (type == XSOCKET_V6) {
        return xsocket_recv6(fd, x, xlen, ip, port, id);
    }
    errno = EPROTO;
    return -1;
}
