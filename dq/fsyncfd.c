/*
20130115
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fsyncfd.h"

int fsyncfd(int fd) {

    struct stat st;

    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        if (fsync(fd) == -1) return -1;
    }
    return 0;
}

