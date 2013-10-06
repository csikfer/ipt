#!/bin/sh

PATH=$PATH:/sbin:/usr/sbin

PLIB="/usr/lib/perl5/site_perl/5.8.5"

if [ "$1" == "remove" ]
then
chkconfig --del ipt
rm -f /usr/local/bin/ipt
rm -f $PLIB/iptcon.pm
rm -f /etc/init.d/ipt
else
install -o root ipt        /usr/local/bin/
install -o root iptcon.pm  $PLIB/
install -o root ipt.sh     /etc/init.d/ipt
chkconfig --add ipt
fi
