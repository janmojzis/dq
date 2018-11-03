#include <unistd.h>
#include "buffer.h"

long long buffer_unixread(int fd, char *x, long long xlen) {

    if (xlen > 1048576) xlen = 1048576;
    return read(fd, x, xlen);
}

