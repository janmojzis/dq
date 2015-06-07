#!/bin/sh -e

build="`pwd`/build"
source="`pwd`"
bin="${build}/bin"

cat "${source}/dq/TARGETS" |\
while read x
do
  [ -x "${bin}/${x}" ] || \
    ( 
      echo "=== `date` === $x not compiled, compile first!"
      exit 111; 
    ) || exit 111
done || exit 111

#bin
confbin="`head -1 conf-bin`"
x=dq
echo "=== `date` ===   installing build/bin/${x} -> $1/${confbin}/${x}"
mkdir -p "$1/${confbin}" || exit 111
cp "${bin}/${x}" "$1/${confbin}" || exit 111
chmod 755 "$1/${confbin}/${x}" || exit 111
chown 0:0 "$1/${confbin}/${x}" || exit 111
echo "=== `date` === finishing"

#sbin
confsbin="`head -1 conf-sbin`"
x=dqcache
echo "=== `date` ===   installing build/bin/${x} -> $1/${confsbin}/${x}"
mkdir -p "$1/${confsbin}" || exit 111
cp "${bin}/dqcache" "$1/${confsbin}" || exit 111
chmod 755 "$1/${confsbin}/${x}" || exit 111
chown 0:0 "$1/${confsbin}/${x}" || exit 111
echo "=== `date` === finishing"

exit 0
