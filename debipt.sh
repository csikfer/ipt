#!/bin/bash
#
### BEGIN INIT INFO
# Provides:          ipt
# Required-Start:    $syslog $time
# Required-Stop:     $syslog $time $networking
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Set iptables
# Description:       Set iptables rules
### END INIT INFO

# Source function library.
. /lib/lsb/init-functions

SOURCE=/etc/ipt.conf
LOG=/var/log/ipt.log
IPT=/usr/local/bin/ipt

if [ ! -f $SOURCE ]
then
   log_warning_msg "Not found: $SOURCE source file."
   exit 1;
fi
if [ ! -x $IPT ]
then
   log_warning_msg "Not found: $IPT executable file."
   exit 1
fi


#
#	See how we were called.
#

start() {
    log_daemon_msg "Starting ipt(iptables)" "ipt"
    $IPT start <$SOURCE >$LOG 2>&1
    log_end_msg $?
}

stop() {
    log_daemon_msg "Stopping ipt(iptables)" "ipt"
    $IPT stop >/dev/null 2>&1
    log_end_msg $?
}


restart() {
    log_daemon_msg "Restarting ipt(iptables)" "ipt"
    $IPT restart <$SOURCE >$LOG 2>&1
    log_end_msg $?
}	

check() {
    echo -n "Check ipt source: "
    $IPT check <$SOURCE >$LOG 2>&1
    if [ $? -eq 0 ]; then
        log_success_msg "$SOURCE file is good"
    else
        log_failure_msg "$SOURCE file is wrong"
    fi
    exit 0
}

case "$1" in
start)
	start
	;;
stop)
	stop
	;;
reload|restart)
	restart
	;;
check)
	check
	;;
*)
	log_action_msg echo "Usage: $0 {start|stop|restart|reload|check}"
	exit 2
esac


