/*
20131117
Jan Mojzis
Public domain.
*/

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "hasipv6.h"
#include "blocking.h"
#include "e.h"
#include "xsocket.h"

int xsocket_tcp(int type) {

    int s;
#ifdef HASIPV6
    int opt = 1;
#endif

    if (type == XSOCKET_V6) {
#ifdef HASIPV6
        s = socket(PF_INET6, SOCK_STREAM, 0);
        if (s == -1) return -1;
        if (fcntl(s, F_SETFD, 1) == -1) { close(s); return -1; }
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt) == -1) { close(s); return -1; }
        blocking_disable(s);
        return s;
#endif
        errno = EPROTONOSUPPORT;
        return -1;
    }

    if (type == XSOCKET_V4) {
        s = socket(PF_INET, SOCK_STREAM, 0);
        if (s == -1) return -1;
        if (fcntl(s, F_SETFD, 1) == -1) { close(s); return -1; }
        blocking_disable(s);
        return s;
    }

    errno = EPROTO;
    return -1;
}
