#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int fd = -1;

void randombytes(unsigned char *x, unsigned long long n) {

    int i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) break;
            sleep(1);
        }
    }

    while (n > 0) {
        if (n < 1048576) i = n; else i = 1048576;

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        n -= i;
    }
}
