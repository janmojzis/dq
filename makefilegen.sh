#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "CFLAGS+=-O3 -fno-strict-overflow -fwrapv -Wno-parentheses -Wundef -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wdeclaration-after-statement -Wshadow -Wno-unused-function -Wno-overlength-strings -Wno-long-long -Wall -pedantic"
    echo "LDFLAGS?="
    echo "DESTDIR?="
    echo 

    i=0
    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        if [ $i -eq 0 ]; then
          echo "BINARIES=${x}"
        else
          echo "BINARIES+=${x}"
        fi
        i=`expr $i + 1`
      fi
    done
    echo

    echo "all: \$(BINARIES)"
    echo 

    touch haslibrandombytes.h haslib25519.h
    for file in `ls *.c`; do
      (
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done
    rm -f haslibrandombytes.h haslib25519.h

    i=0
    for file in `ls *.c`; do
      if ! grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$/.o/'`
        if [ $i -eq 0 ]; then
          echo "OBJECTS=${x}"
        else
          echo "OBJECTS+=${x}"
        fi
        i=`expr $i + 1`
      fi
    done
    echo

    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "${x}: ${x}.o \$(OBJECTS) librandombytes.lib lib25519.lib"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS) \`cat librandombytes.lib\` \`cat lib25519.lib\`"
        echo 
      fi
    done
    echo

    # try librandombytes
    echo "haslibrandombytes.h: trylibrandombytes.sh"
    echo "	env CC=\$(CC) ./trylibrandombytes.sh && echo '#define HASLIBRANDOMBYTES 1' > haslibrandombytes.h || true > haslibrandombytes.h"
    echo
    echo "librandombytes.lib: trylibrandombytes.sh"
    echo "	env CC=\$(CC) ./trylibrandombytes.sh && echo '-lrandombytes' > librandombytes.lib || true > librandombytes.lib"
    echo

    # try lib25519
    echo "haslib25519.h: trylib25519.sh"
    echo "	env CC=\$(CC) ./trylib25519.sh && echo '#define HASLIB25519 1' > haslib25519.h || true > haslib25519.h"
    echo
    echo "lib25519.lib: trylib25519.sh"
    echo "	env CC=\$(CC) ./trylib25519.sh && echo '-l25519' > lib25519.lib || true > lib25519.lib"
    echo

    echo "install: dq dqcache dqcache-makekey dqcache-start"
    echo "	install -D -m 0755 dq \$(DESTDIR)/usr/bin/dq"
    echo "	install -D -m 0755 dqcache \$(DESTDIR)/usr/sbin/dqcache"
    echo "	install -D -m 0755 dqcache-makekey \$(DESTDIR)/usr/sbin/dqcache-makekey"
    echo "	install -D -m 0755 dqcache-start \$(DESTDIR)/usr/sbin/dqcache-start"
    echo

    echo "clean:"
    echo "	rm -f *.o *.out \$(BINARIES) haslibrandombytes.h librandombytes.lib haslib25519.h lib25519.lib"
    echo 

  ) > Makefile
)
