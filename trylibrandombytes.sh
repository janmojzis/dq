#!/bin/sh

if [ x"${CC}" = x ]; then
  echo '$CC not set'
  exit 1
fi

cleanup() {
  ex=$?
  rm -f trylibrandombytes trylibrandombytes.c
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  echo '#include <randombytes.h>'
  echo ''
  echo 'static unsigned char buf[1024];'
  echo ''
  echo ''
  echo 'int main(void) {'
  echo '    randombytes(buf, sizeof buf);'
  echo '    return buf[0];'
  echo '}'
) > trylibrandombytes.c

${CC} -o trylibrandombytes trylibrandombytes.c -lrandombytes 1>/dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "trylibrandombytes: librandombytes detected"
  exit 0
else
  echo "trylibrandombytes: librandombytes not detected"
  exit 1
fi
