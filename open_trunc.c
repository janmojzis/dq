#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "open.h"

int open_trunc(const char *fn)
{
#ifdef O_CLOEXEC
  return open(fn,O_CREAT | O_WRONLY | O_NONBLOCK | O_TRUNC | O_CLOEXEC,0644);
#else
  int fd = open(fn,O_CREAT | O_WRONLY | O_NONBLOCK | O_TRUNC,0644);
  if (fd == -1) return -1;
  fcntl(fd,F_SETFD,1);
  return fd;
#endif
}
