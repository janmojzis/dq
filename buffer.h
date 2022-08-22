#ifndef _BUFFER_H____
#define _BUFFER_H____

typedef struct buffer {
    char *x;
    long long p;
    long long n;
    int fd;
    long long (*op)();
} buffer;

#define BUFFER_INIT(op, fd, buf, len) { (buf), 0, (len), (fd), (op) }
#define BUFFER_INSIZE 8192
#define BUFFER_OUTSIZE 8192
#define BUFFER_ERRSIZE 256

extern void buffer_init(buffer *, long long (*op)(), int, char *, long long);

extern int buffer_flush(buffer *);
extern int buffer_putalign(buffer *, const char *, long long);
extern int buffer_put(buffer *, const char *, long long);
extern int buffer_putflush(buffer *, const char *, long long);
extern int buffer_putsalign(buffer *, const char *);
extern int buffer_puts(buffer *, const char *);
extern int buffer_putsflush(buffer *, const char *);

#define buffer_PUTC(s,c) \
  ( ((s)->n != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : buffer_put((s),&(c),1) \
  )

extern long long buffer_get(buffer *, char *, long long);
extern long long buffer_bget(buffer *, char *, long long);
extern long long buffer_feed(buffer *);

extern char *buffer_peek(buffer *);
extern void buffer_seek(buffer *, long long);

#define buffer_PEEK(s) ( (s)->x + (s)->n )
#define buffer_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define buffer_GETC(s,c) \
  ( ((s)->p > 0) \
    ? ( *(c) = (s)->x[(s)->n], buffer_SEEK((s),1), 1 ) \
    : buffer_get((s),(c),1) \
  )

extern int buffer_copy(buffer *,buffer *);

extern long long buffer_unixread(int, char *, long long);
extern long long buffer_unixwrite(int, const char *, long long);

#define buffer_PEEK(s) ( (s)->x + (s)->n )
#define buffer_SEEK(s, len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

extern buffer *buffer_0;
extern buffer *buffer_0small;
extern buffer *buffer_1;
extern buffer *buffer_1small;
extern buffer *buffer_2;

#endif
