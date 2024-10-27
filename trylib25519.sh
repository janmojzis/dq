#!/bin/sh

if [ x"${CC}" = x ]; then
  echo '$CC not set'
  exit 1
fi

cleanup() {
  ex=$?
  rm -f trylib25519 trylib25519.c
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  echo '#include <lib25519.h>'
  echo ''
  echo 'static unsigned char k[lib25519_dh_BYTES];'
  echo 'static unsigned char k2[lib25519_dh_BYTES];'
  echo 'static unsigned char pk[lib25519_dh_PUBLICKEYBYTES];'
  echo 'static unsigned char pk2[lib25519_dh_PUBLICKEYBYTES];'
  echo 'static unsigned char sk[lib25519_dh_SECRETKEYBYTES];'
  echo ''
  echo ''
  echo 'int  main(void) {'
  echo '    unsigned char diff = 0;'
  echo '    long long i;'
  echo ''
  echo '    lib25519_dh_keypair(pk, sk);'
  echo '    lib25519_nG_montgomery25519(pk2, sk);'
  echo '    for (i = 0; i < lib25519_dh_PUBLICKEYBYTES; ++i) diff |= pk[i] ^ pk2[i];'
  echo '    if (diff) return 1;'
  echo ''
  echo '    lib25519_dh_keypair(pk, sk);'
  echo '    sk[0] &= 248;'
  echo '    sk[31] &= 127;'
  echo '    sk[31] |= 192;'
  echo '    lib25519_nG_merged25519(pk2, sk);'
  echo '    for (i = 0; i < lib25519_dh_PUBLICKEYBYTES; ++i) diff |= pk[i] ^ pk2[i];'
  echo '    if (diff) return 1;'
  echo ''
  echo '    lib25519_dh(k,pk,sk);'
  echo '    lib25519_nP(k2,sk,pk);'
  echo '    for (i = 0; i < lib25519_dh_BYTES; ++i) diff |= k[i] ^ k2[i];'
  echo '    if (diff) return 2;'
  echo '    return 0;'
  echo '}'
) > trylib25519.c

${CC} -o trylib25519 trylib25519.c -l25519 1>/dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "trylib25519: lib25519 detected"
  exit 0
else
  echo "trylib25519: lib25519 not detected"
  exit 1
fi
