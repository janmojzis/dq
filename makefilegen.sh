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

    for file in `ls *.c`; do
      (
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done

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
        echo "${x}: ${x}.o \$(OBJECTS)"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS)"
        echo 
      fi
    done
    echo

    echo "install: dq dqcache dqcache-makekey dqcache-start"
    echo "	install -D -m 0755 dq \$(DESTDIR)/usr/bin/dq"
    echo "	install -D -m 0755 dqcache \$(DESTDIR)/usr/sbin/dqcache"
    echo "	install -D -m 0755 dqcache-makekey \$(DESTDIR)/usr/sbin/dqcache-makekey"
    echo "	install -D -m 0755 dqcache-start \$(DESTDIR)/usr/sbin/dqcache-start"
    echo

    echo "clean:"
    echo "	rm -f *.o *.out \$(BINARIES)"
    echo 

  ) > Makefile
)
