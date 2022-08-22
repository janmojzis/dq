#include "crypto_core_hsalsa20.h"
#include "crypto_scalarmult_curve25519.h"
#include "crypto_secretbox_xsalsa20poly1305.h"
#include "randombytes.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

static const unsigned char zero[16] = {0};
static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_box_curve25519xsalsa20poly1305_tinynacl_beforenm(
  unsigned char *k,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char s[32];
  crypto_scalarmult_curve25519(s,sk,pk);
  return crypto_core_hsalsa20(k, zero, s, sigma);
}

int crypto_box_curve25519xsalsa20poly1305_tinynacl_afternm(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  return crypto_secretbox_xsalsa20poly1305(c,m,mlen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305_tinynacl_open_afternm(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  return crypto_secretbox_xsalsa20poly1305_open(m,c,clen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305_tinynacl(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[32];
  crypto_box_curve25519xsalsa20poly1305_tinynacl_beforenm(k,pk,sk);
  return crypto_box_curve25519xsalsa20poly1305_tinynacl_afternm(c,m,mlen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305_tinynacl_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[32];
  crypto_box_curve25519xsalsa20poly1305_tinynacl_beforenm(k,pk,sk);
  return crypto_box_curve25519xsalsa20poly1305_tinynacl_open_afternm(m,c,clen,n,k);
}

int crypto_box_curve25519xsalsa20poly1305_tinynacl_keypair(
  unsigned char *pk,
  unsigned char *sk
)
{
  randombytes(sk,32);
  return crypto_scalarmult_curve25519_base(pk,sk);
}
