#include "e.h"
#include "byte.h"
#include "buffer.h"


static int oneread(long long (*op)(int, char *, long long), int fd, char *buf, long long len) {

    long long r;

    if (len < 0) { errno = EINVAL; return -1; }

    for(;;) {
        r = op(fd,buf,len);
        if (r == -1) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
        }
        return r;
    }
}


static long long getthis(buffer *s, char *buf, long long len) {

    if (len < 0) { errno = EINVAL; return -1; }

    if (len > s->p) len = s->p;
    s->p -= len;
    byte_copy(buf, len, s->x + s->n);
    s->n += len;
    return len;
}


long long buffer_feed(buffer *s) {

    long long r;

    if (s->p > 0) return s->p;
    r = oneread(s->op, s->fd, s->x, s->n);
    if (r <= 0) return r;
    s->p = r;
    s->n -= r;
    if (s->n > 0) byte_copyr(s->x + s->n, r, s->x);
    return r;
}


long long buffer_bget(buffer *s, char *buf, long long len) {

    long long r;

    if (len < 0) { errno = EINVAL; return -1; }
    if (s->p > 0) return getthis(s, buf, len);
    if (s->n <= len) return oneread(s->op, s->fd, buf, s->n);
    r = buffer_feed(s); if (r <= 0) return r;
    return getthis(s, buf, len);
}

long long buffer_get(buffer *s, char *buf, long long len) {

    long long r;

    if (len < 0) { errno = EINVAL; return -1; }
    if (s->p > 0) return getthis(s, buf, len);
    if (s->n <= len) return oneread(s->op, s->fd, buf, len);
    r = buffer_feed(s); if (r <= 0) return r;
    return getthis(s, buf, len);
}

char *buffer_peek(buffer *s) {
    return s->x + s->n;
}

void buffer_seek(buffer *s, long long len) {
    if (len < 0) len = 0;
    s->n += len;
    s->p -= len;
}
