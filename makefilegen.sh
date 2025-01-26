#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "CFLAGS+=-O3 -fno-strict-overflow -fwrapv -Wno-parentheses -Wundef -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wdeclaration-after-statement -Wshadow -Wno-unused-function -Wno-overlength-strings -Wno-long-long -Wall -pedantic -Icryptoint"
    echo "LDFLAGS?="
    echo "CPPFLAGS?="
		echo
    echo "DESTDIR?="
    echo "PREFIX?=/usr/local"
    echo
    echo "INSTALL?=install"
    echo 

    # binaries
    i=0
    for file in `ls -1 *.c | grep -v '^has'`; do
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

    for file in `ls -1 has*.c`; do
      hfile=`echo ${file} | sed 's/\.c/.h/'`
      touch "${hfile}"
    done
    for file in `ls -1 *.c | grep -v '^has'`; do
      (
        gcc -Icryptoint -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done
    for file in `ls -1 has*.c`; do
      hfile=`echo ${file} | sed 's/\.c/.h/'`
      rm -f "${hfile}"
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

    for file in `ls *.c | grep -v '^has'`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "${x}: ${x}.o \$(OBJECTS) libs"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS) \`cat libs\`"
        echo 
      fi
    done
    echo

    for cfile in `ls -1 has*.c`; do
      hfile=`echo ${cfile} | sed 's/\.c/.h/'`
      lfile=`echo ${cfile} | sed 's/\.c/.log/'`
      touch "${hfile}"
      echo "${hfile}: tryfeature.sh ${cfile} libs"
      echo "	env CC=\"\$(CC)\" CFLAGS=\"\$(CFLAGS)\" LDFLAGS=\"\$(LDFLAGS) \`cat libs\`\" ./tryfeature.sh ${cfile} >${hfile} 2>${lfile}"
      echo "	cat ${hfile}"
      echo
    done

    echo "libs: trylibs.sh"
    echo "	env CC=\"\$(CC)\" ./trylibs.sh -lsocket -lnsl -lrandombytes -l25519 >libs 2>libs.log"
    echo "	cat libs"
    echo

    echo "install: dq dqcache dqcache-makekey dqcache-start"
    echo "	mkdir -p \$(DESTDIR)\$(PREFIX)/bin"
    echo "	mkdir -p \$(DESTDIR)\$(PREFIX)/sbin"
    echo "	mkdir -p \$(DESTDIR)\$(PREFIX)/share/man/man1"
    echo "	mkdir -p \$(DESTDIR)\$(PREFIX)/share/man/man8"
    echo "	\$(INSTALL) -m 0755 dq \$(DESTDIR)\$(PREFIX)/bin/dq"
    echo "	\$(INSTALL) -m 0755 dqcache \$(DESTDIR)\$(PREFIX)/sbin/dqcache"
    echo "	\$(INSTALL) -m 0755 dqcache-makekey \$(DESTDIR)\$(PREFIX)/sbin/dqcache-makekey"
    echo "	\$(INSTALL) -m 0755 dqcache-start \$(DESTDIR)\$(PREFIX)/sbin/dqcache-start"
    echo "	\$(INSTALL) -m 0644 man/dq.1 \$(DESTDIR)\$(PREFIX)/share/man/man1/dq.1"
    echo "	\$(INSTALL) -m 0644 man/dqcache.8 \$(DESTDIR)\$(PREFIX)/share/man/man8/dqcache.8"
    echo "	\$(INSTALL) -m 0644 man/dqcache-makekey.8 \$(DESTDIR)\$(PREFIX)/share/man/man8/dqcache-makekey.8"
    echo "	\$(INSTALL) -m 0644 man/dqcache-start.8 \$(DESTDIR)\$(PREFIX)/share/man/man8/dqcache-start.8"
    echo

    echo "clean:"
    echo "	rm -f *.log has*.h \$(OBJECTS) \$(BINARIES) libs"
    echo 

  ) > Makefile
)
