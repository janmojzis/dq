#include <sys/types.h>
#include <dir.h>
#include <stdio.h>

int main(int argc,char **argv){

  DIR *dir;
  struct direct *d;

  dir=0; d = 0;

  printf("/* Public domain. */\n\n");
  printf("#ifndef _DIRENTRY_H____\n");
  printf("#define _DIRENTRY_H____\n\n");
  printf("#include <sys/types.h>\n");
  printf("#include <dir.h>\n\n");
  printf("#define direntry struct direct\n\n");
  printf("#endif /* _DIRENTRY_H____ */\n");
  return 0;
}
