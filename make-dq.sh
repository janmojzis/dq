#!/bin/sh -e

top="`pwd`"
build="`pwd`/build"
bin="${build}/bin"
man="${build}/man"
lib="${build}/lib"
include="${build}/include"
log="${build}/log"
work="${build}/work"
contribdir="`pwd`/build-contrib"

rm -rf "${build}"
mkdir -p "${build}"
mkdir -p "${bin}"
mkdir -p "${man}"
mkdir -p "${lib}"
mkdir -p "${include}"

exec 5>"${log}"
exec 2>&5
exec </dev/null

log0() {
  echo "=== `date` === $@" >&5
}

log1() {
  echo "=== `date` === $@"
  echo "=== `date` === $@" >&5
}

log2() {
  echo "=== `date` ===   $@"
  echo "=== `date` ===   $@" >&5
}

version=`head -1 "${top}/debian/changelog"  | cut -d '(' -f2 | cut -d ')' -f1` #XXX

LANG=C
export LANG

log0 "uname -a: `uname -a || :`"
log0 "uname -F: `uname -F || :`"
log0 "uname -M: `uname -M || :`"
log0 "ulimit -a: `echo; ulimit -a || :`"

log1 "obtaining compiler"
rm -rf "${work}"
mkdir -p "${work}"
(
  cd "${work}"
  (
    if [ x"${CC}" != x ]; then
      echo "${CC} "
    fi
    cat "${top}/conf-cc"
  ) | while read compiler
  do
    echo 'int main(void) { return 0; }' > try.c
    ${compiler} -o try try.c || { log2 "${compiler} failed"; continue; }
    log2 "${compiler} ok"
    echo "${compiler}" > compiler
    break
  done
)
compiler=`head -1 "${work}/compiler"`
log1 "finishing"

log1 "checking compiler options"
rm -rf "${work}"
mkdir -p "${work}"
(
  cd "${work}"
  cflags=`cat "${top}/conf-cflags" || :`
  cflags="${CPPFLAGS} ${CFLAGS} ${LDFLAGS} ${cflags}"

  for i in ${cflags}; do
    echo 'int main(void) { return 0; }' > try.c
    ${compiler} "${i}" -o try try.c || { log2 "${i} failed"; continue; }
    options="${options} ${i}"
    log2 "${i} ok"
  done
  echo ${options} > options
)
compilerorig=${compiler}
compiler="${compiler} `cat ${work}/options`"
log2 "${compiler}"
log1 "finishing"

log1 "checking libs"
rm -rf "${work}"
mkdir -p "${work}"
(
  cd "${work}"
  (
    cat "${top}/conf-libs" || :
  ) | (
    exec 9>syslibs
    while read i; do
      echo 'int main(void) { return 0; }' > try.c
      ${compiler} ${i} -o try try.c || { log2 "${i} failed"; continue; }
      echo "${i}" >&9
      log2 "${i} ok"
    done
  )
)
libs=`cat "${work}/syslibs"`
log1 "finishing"

log1 "checking \$LIBS"
if [ x"${LIBS}" != x ]; then
  rm -rf "${work}"
  mkdir -p "${work}"
  (
    cd "${work}"
    for i in ${LIBS}; do
      echo 'int main(void) { return 0; }' > try.c
      ${compiler} ${i} -o try try.c || { log2 "${i} failed"; continue; }
      syslibs="${i} ${syslibs}"
      log2 "${i} ok"
    done
    echo ${syslibs} > syslibs
 )
fi
libsorig=${libs}
libs="${libs} `cat ${work}/syslibs`"
log1 "finishing"

log1 "building sysdep headers"
rm -rf "${work}"
mkdir -p "${work}"
cp -pr sysdep/* "${work}"
(
  cd "${work}"
  sh list | (
    while read target source
    do
      [ -f "${include}/${target}" ] && continue
      rm -f "${source}" "${target}.tmp" 
      ${compiler} -O0 -o "${source}" "${source}.c" ${libs} || continue
      ./${source} > "${target}.tmp" || continue
      cp "${target}.tmp" "${include}/${target}"
      log2 "${target} ${source}"
    done
  )
)
log1 "finishing"

log1 "starting crypto lib"
rm -rf "${work}"
mkdir -p "${work}"
cp -pr crypto/* "${work}"
(
  cd "${work}"
  cat CRYPTOSOURCES\
  | while read x
  do
    ${compiler} -I"${include}" -c "${x}.c" || { log2 "libtinynacl.a failed ... see the log ${log}"; exit 111; }
  done || exit 111
  ar cr "${lib}/libtinynacl.a" `cat CRYPTOLIBS` || exit 0
)
log2 "libtinynacl.a ok"
log1 "finishing"

origlibs="${origlibs} ${lib}/libtinynacl.a"
libs="${libs} ${lib}/libtinynacl.a"

log1 "starting crypto headers"
rm -rf "${work}"
mkdir -p "${work}"
cp -p crypto/CRYPTOPRIMITIVES "${work}"
cp -pr crypto-tests/*test.c "${work}"
cp -pr crypto-tests/*.h "${work}"
cp -pr crypto-tests/*.data "${work}" 2>/dev/null || :
(
  cd "${work}"
  cat CRYPTOPRIMITIVES\
  | while read primitive checkflag
  do
    if [ "x${checkflag}" = x0 ]; then
      cp -p "${top}/crypto/${primitive}.h" "${include}"
      continue;
    fi
    testf=`echo "${primitive}" | sed 's/$/test/'`
    (
      echo '#include <stdio.h>'
      echo "#include <${primitive}.h>"
      echo 'int main(void) {'
      echo "#ifdef ${primitive}_PRIMITIVE"
      echo "printf(\"%s\\\\n\", ${primitive}_PRIMITIVE);"
      echo '#else'
      echo "#ifdef ${primitive}_IMPLEMENTATION"
      echo "printf(\"%s\\\\n\", ${primitive}_IMPLEMENTATION);"
      echo '#endif'
      echo "#ifdef ${primitive}_implementation"
      echo "printf(\"%s\\\\n\", ${primitive}_implementation);"
      echo '#endif'
      echo '#endif'
      echo 'return 0; }'
    ) > try.c
    #try ext. crypto library
    log0 "trying: ext. ${primitive}:"
    if ${compiler} -c "${testf}.c" ${libs}; then
      if ${compiler} -o "${testf}" "${testf}.o" ${libs}; then
        if ${compiler} -o try try.c; then
          if /bin/sh -ec "./${testf}"; then
            log2 "${primitive}.h (`./try`) ok"
            echo "#include <${primitive}.h>" >> crypto.h
            continue
          else
            log2 "${primitive}.h (`./try`) failed"
          fi
        fi
      fi
    fi
    #try int. crypto library
    log0 "trying: int. ${primitive}:"
    if cp -p "${top}/crypto/${primitive}.h" . ; then
      if ${compilerorig} -I. -I"$include" -o "${testf}" "${testf}.c" ${origlibs}; then
        if ${compilerorig} -I. -I"$include" -o try try.c; then
          if /bin/sh -ec "./${testf}"; then
            log2 "${primitive}.h (`./try`) ok"
            echo "#include \"${primitive}.h\"" >> crypto.h
            cp -p "${primitive}.h" "${include}"
            continue
          fi
        fi
      fi
    fi
    log2 "${primitive}.h failed ... see the log ${log}"
    exit 111
  done || exit 111
  cp crypto.h "${include}/crypto.h"
)
log1 "finishing"

rm -rf "${work}"
mkdir -p "${work}"
cp -pr dq/* "${work}"
#cp -pr dq-tests/*test.c "${work}"
#cp -pr dq-tests/*.h "${work}"
#cp -pr _dq/* "${work}" 2>/dev/null || :
(
  cd "${work}"
  log1 "starting dq objects"
  touch SOURCES TARGETS _TARGETS
  cat SOURCES TARGETS _TARGETS\
  | while read x
  do
    ${compiler} "-DCOMPILER=\"${compilerorig}\"" "-DVERSION=\"${version}\"" -I"${include}" -c "${x}.c" || { log2 "${x}.o failed ... see the log ${log}"; exit 111; }
    log2 "${x}.o ok"
  done || exit 111
  ar cr libdq.a `cat LIBS` || exit 111
  log1 "finishing"

  log1 "starting dq"
  cat TARGETS \
  | while read x
  do
    ${compiler} -I"${include}" -o "${x}" "${x}.o" libdq.a ${libs} || { log2 "${x} failed ... see the log ${log}"; exit 111; }
    cp -p "${x}" "${bin}/${x}"
    log2 "${x} ok"
  done || exit 111
  log1 "finishing"

) || exit 111


log1 "starting manpages"
cp -pr man/* "${man}"
log1 "finishing"


echo "=== `date` === counting words of code"
rm -rf "${work}"
mkdir -p "${work}"

for dir in sysdep dq crypto; do
  (
    cd "${dir}"
    cat *.c *.h > "${work}/${dir}" || :
  )

  (
    cd "${work}"
    cat "${dir}" \
    | (
      cpp -fpreprocessed || gcpp -fpreprocessed
    ) | (
      x=`sed 's/[_a-zA-Z0-9][_a-zA-Z0-9]*/x/g' | tr -d ' \012' | wc -c | tr -d ' '`
      log2 "${dir} ${x}"
    )
  )
done
(
  cd "${work}"
  cat * \
  | (
    cpp -fpreprocessed || gcpp -fpreprocessed
  ) | (
    x=`sed 's/[_a-zA-Z0-9][_a-zA-Z0-9]*/x/g' | tr -d ' \012' | wc -c | tr -d ' '`
    log2 "${x} words of code"
  )
)
log1 "finishing"
exit 0
