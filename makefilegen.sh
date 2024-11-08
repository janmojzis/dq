#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "CFLAGS+=-O3 -fno-strict-overflow -fwrapv -Wno-parentheses -Wundef -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wdeclaration-after-statement -Wshadow -Wno-unused-function -Wno-overlength-strings -Wno-long-long -Wall -pedantic"
    echo "LDFLAGS?="
    echo "CPPFLAGS?="
    echo "DESTDIR?="
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
        gcc -MM "${file}"
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
    echo "	env CC=\"\$(CC)\" ./trylibs.sh -lsocket -lnsl -lrandombytes -l25519 >libs"
    echo "	cat libs"
    echo

    echo "install: dq dqcache dqcache-makekey dqcache-start"
    echo "	install -D -m 0755 dq \$(DESTDIR)/usr/bin/dq"
    echo "	install -D -m 0755 dqcache \$(DESTDIR)/usr/sbin/dqcache"
    echo "	install -D -m 0755 dqcache-makekey \$(DESTDIR)/usr/sbin/dqcache-makekey"
    echo "	install -D -m 0755 dqcache-start \$(DESTDIR)/usr/sbin/dqcache-start"
    echo

    echo "clean:"
    echo "	rm -f *.log has*.h \$(OBJECTS) \$(BINARIES) libs"
    echo 

  ) > Makefile
)
