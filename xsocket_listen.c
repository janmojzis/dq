#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "e.h"
#include "xsocket.h"

int xsocket_listen(int fd, long long backlog) {
    if (backlog < 0 || backlog > 1048576) { errno = EPROTO; return -1; }
    return listen(fd, backlog);
}
