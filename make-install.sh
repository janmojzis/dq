#!/bin/sh -e

build="`pwd`/build"
source="`pwd`"
bin="${build}/bin"
man="${build}/man"

cat "${source}/dq/TARGETS" |\
while read x
do
  [ -x "${bin}/${x}" ] || \
    ( 
      echo "=== `date` === $x not compiled, compile first!"
      exit 111; 
    ) || exit 111
done || exit 111

echo "=== `date` === installing bin directory"
cat "${source}/dq/TARGETS" |\
while read x
do
  if [ x"${x}" = xdq ]; then
    confbin="`head -1 conf-bin`"
  else
    confbin="`head -1 conf-sbin`"
  fi
  echo "=== `date` ===   installing build/bin/${x} -> $1/${confbin}/${x}"
  mkdir -p "$1/${confbin}" || exit 111
  cp "${bin}/${x}" "$1/${confbin}" || exit 111
  chmod 755 "$1/${confbin}/${x}" || exit 111
  chown 0:0 "$1/${confbin}/${x}" || exit 111
done
echo "=== `date` === finishing"

#man
confman="`head -1 conf-man`"
echo "=== `date` === installing man directory"
ls "${man}" | sort |\
while read x
do
  n=`echo "${x}" | cut -d'.' -f2`
  mkdir -p "$1/${confman}/man${n}" || exit 111
  cp "${man}/${x}" "$1/${confman}/man${n}" || exit 111
  echo "=== `date` ===   installing ${man}/${x} -> $1/${confman}/man${n}/${x}"
done || exit 111
echo "=== `date` === finishing"

exit 0
