/* taken from nacl-20110221, from curvecp/randommod.c (public-domain) */
#include "randombytes.h"
#include "randommod.h"

/* XXX: current implementation is limited to n<2^55 */

long long randommod(long long n)
{
  long long result = 0;
  long long j;
  unsigned char r[32];
  if (n <= 1) return 0;
  randombytes(r,32);
  for (j = 0;j < 32;++j) result = (result * 256 + (unsigned long long) r[j]) % n;
  return result;
}
