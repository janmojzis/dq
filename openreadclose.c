#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "open.h"
#include "e.h"
#include "byte.h"
#include "openreadclose.h"

int openreadclose(const char *fn, stralloc *sa, long long bufsize) {

    int fd;
    long long r;
    struct stat st;

    if (bufsize <= 1) bufsize = 32;

    fd = open_read(fn);
    if (fd == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    if (fstat(fd, &st) == -1) { close(fd); return -1; }
    if (!stralloc_readyplus(sa, st.st_size)) { close(fd); return -1; }
    if (!stralloc_copys(sa, "")) { close(fd); return -1; }

    for (;;) {
        if (!stralloc_readyplus(sa, bufsize)) { close(fd); return -1; }
        r = read(fd, sa->s + sa->len, bufsize);
        if (r == 0) break;
        if (r == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
            close(fd);
            return -1;
        }
        sa->len += r;
    }
    close(fd);
    return 1;
}
