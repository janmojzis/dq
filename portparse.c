#include "portparse.h"

int portparse(unsigned char *y,const char *x)
{
  long long d = 0;
  long long j;
  if (!x) return 0; 
  for (j = 0;j < 5 && x[j] >= '0' && x[j] <= '9';++j)
    d = d * 10 + (x[j] - '0');
  if (j == 0) return 0;
  if (x[j]) return 0;
  if (d > 65535) return 0;
  y[0] = d >> 8;
  y[1] = d;
  return 1;
}
