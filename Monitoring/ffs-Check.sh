#!/bin/sh

#exit 0

LOGFILE=/var/freifunk/logs/monitoring.log

git -C /var/freifunk/peers-ffs pull --rebase=true
echo $?

date > $LOGFILE
/usr/local/bin/ffs-Monitoring.py --gitrepo /var/freifunk/peers-ffs --logs /var/freifunk/logs --json /var/freifunk/json >> $LOGFILE
echo $?
