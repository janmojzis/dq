#!/bin/sh

### BEGIN INIT INFO
# Provides:             dqcache
# Required-Start:       $remote_fs $syslog
# Required-Stop:        $remote_fs $syslog
# Default-Start:        2 3 4 5
# Default-Stop:         
# Short-Description:    DNS/DNSCurve recursive server
### END INIT INFO

set -e

NAME=dqcache
DAEMON="/usr/sbin/${NAME}"
PIDFILE="/var/run/${NAME}.pid"
SCRIPTNAME="/etc/init.d/${NAME}"
DESC="DNS/DNSCurve recursive server"

[ -x "${DAEMON}" ] || exit 0
[ -r "/etc/default/${NAME}" ] && . "/etc/default/${NAME}"
. /lib/lsb/init-functions

case "$1" in
  start)
	log_daemon_msg "Starting ${DESC}" "${NAME}"
        if start-stop-daemon --start --quiet --oknodo --pidfile "${PIDFILE}" --exec /usr/sbin/dqcache-wrapper.sh -b; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;
  stop)
	log_daemon_msg "Stopping ${DESC}" "${NAME}"
        if start-stop-daemon --stop --quiet --oknodo --pidfile "${PIDFILE}"; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
	;;
  restart|force-reload)
	$0 stop
	$0 start
	;;
  status)
	status_of_proc -p "${PIDFILE}" "${DAEMON}" "${NAME}" && exit 0 || exit $?
	;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|rotate|restart|force-reload|status}" >&2
	exit 3
	;;
esac
