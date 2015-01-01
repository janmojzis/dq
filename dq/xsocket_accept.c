/*
20131206
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

static int xsocket_accept6(int s, unsigned char *ip, unsigned char *port, long long *id) {

#ifdef HASIPV6
    struct sockaddr_in6 sa;
    socklen_t salen = sizeof sa;
    int fd;

    byte_zero(&sa, sizeof sa);
    fd = accept(s, (struct sockaddr *)&sa, &salen);
    if (fd == -1) return -1;

    if (((struct sockaddr *)&sa)->sa_family != PF_INET6) { close(fd); errno = EPROTO; return -1; }

    if (ip) byte_copy(ip, 16, &sa.sin6_addr);
    if (port) byte_copy(port, 2, &sa.sin6_port);
    if (id) *id = sa.sin6_scope_id;
    return fd;
#else
    errno = EPROTONOSUPPORT;
    return -1;
#endif

}

static int xsocket_accept4(int s, unsigned char *ip, unsigned char *port, long long *id) {

    struct sockaddr_in sa;
    socklen_t salen = sizeof sa;
    int fd;

    byte_zero(&sa, sizeof sa);
    fd = accept(s, (struct sockaddr *)&sa, &salen);
    if (fd == -1) return -1;

    if (((struct sockaddr *)&sa)->sa_family != PF_INET) { close(fd); errno = EPROTO; return -1; }

    if (ip) byte_copy(ip, 12, "\0\0\0\0\0\0\0\0\0\0\377\377");
    if (ip) byte_copy(ip + 12, 4, &sa.sin_addr);
    if (port) byte_copy(port, 2, &sa.sin_port);
    if (id) *id = 0;
    return fd;
}

int xsocket_accept(int fd, int type, unsigned char *ip, unsigned char *port, long long *id) {

    if (type == XSOCKET_V4) {
        return xsocket_accept4(fd, ip, port, id);
    }
    if (type == XSOCKET_V6) {
        return xsocket_accept6(fd, ip, port, id);
    }
    errno = EPROTO;
    return -1;
}
