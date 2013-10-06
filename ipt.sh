#!/bin/bash
#
#	/etc/rc.d/init.d/ipt.sh
#
# Starts the at daemon
#
# chkconfig: 2345 08 92
# description: Runs commands scheduled by the at command at the time \
#    specified when at was run, and runs batch commands when the load \
#    average is low enough.
# processname: ipt 

# Source function library.
. /etc/init.d/functions

SOURCE=/etc/sysconfig/ipt.txt
LOG=/var/log/ipt.log
IPT=/usr/local/bin/ipt

if [ ! -f $SOURCE ]
then
   echo "Not found: $SOURCE source file."
   exit 1;
fi
if [ ! -x $IPT ]
then
   echo "Not found: $IPT executable file."
   exit 1
fi


#
#	See how we were called.
#

start() {
    echo -n "Starting ipt(iptables): "
    $IPT start <$SOURCE >$LOG 2>&1
    if [ $? -eq 0 ]; then
        success; echo
    else
        failure; echo; exit 1
    fi
    exit 0
}

stop() {
    echo -n "Stopping ipt(iptables): "
    $IPT stop >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        success; echo
    else
        failure; echo; exit 1
    fi
    exit 0
}


restart() {
    echo -n "Restarting ipt(iptables): "
    $IPT restart <$SOURCE >$LOG 2>&1
    if [ $? -eq 0 ]; then
        success; echo
    else
        failure; echo; exit 1
    fi
    exit 0

}	

check() {
    echo -n "Check ipt source: "
    $IPT check <$SOURCE >$LOG 2>&1
    if [ $? -eq 0 ]; then
        success; echo
    else
        failure; echo; exit 1
    fi
    exit 0
}

ifaces() {
    echo -n "Generate iface list in ipt source: "
    $IPT ifaces <$SOURCE >$LOG 2>&1
    if [ $? -eq 0 ]; then
        success; echo
    else
        failure; echo; exit 1
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
ifaces)
	ifaces
	;;
*)
	echo $"Usage: $0 {start|stop|restart|reload|check|ifaces}"
	exit 1
esac


