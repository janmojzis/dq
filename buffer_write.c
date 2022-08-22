#include "writeall.h"
#include "buffer.h"

long long buffer_unixwrite(int fd, const char *x, long long xlen) {

    if (writeall(fd, x, xlen) == -1) return -1;
    return xlen;
}

