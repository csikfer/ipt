#!/bin/sh

PATH=$PATH:/sbin:/usr/sbin

PLIB="/usr/local/lib/site_perl"

if [ "$1" == "remove" ]
then
update-rc.d -f ipt.sh remove
rm -f /usr/local/bin/ipt
rm -f $PLIB/iptcon.pm
rm -f /etc/init.d/ipt.sh
else
install -o root ipt        /usr/local/bin/
mkdir $PLIB
install -o root iptcon.pm  $PLIB/
install -o root debipt.sh     /etc/init.d/ipt.sh
update-rc.d ipt.sh defaults
fi
