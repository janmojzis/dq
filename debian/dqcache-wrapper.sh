#!/bin/sh

. /etc/default/dqcache
export ROOT
export CACHESIZE
export IP

if [ x"${ROOT}" = x ]; then
  echo 'dqcache-wrapper.sh: $ROOT not set' >&2
  exit 111
fi

ID=`expr "$$" + "141500000"`
chown "${ID}.${ID}" "${ROOT}/dump"
chown "${ID}.${ID}" "${ROOT}/dump/dnsdata" 
exec /usr/bin/env UID="${ID}" GID="${ID}" /usr/sbin/dqcache
