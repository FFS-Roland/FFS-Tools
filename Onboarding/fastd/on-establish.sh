#!/bin/sh

LOGFILE=/var/freifunk/logs/vpn00_established.log

date >> $LOGFILE
ps -e | grep "ffs-Onboarding" >> $LOGFILE
echo Starting ... >> $LOGFILE

/usr/local/bin/ffs-Onboarding.py --fastd $INTERFACE --batman bat00 --peerkey $PEER_KEY --gitrepo /var/freifunk/peers-ffs --json /var/freifunk/json --blacklist /etc/fastd/$INTERFACE/blacklist >> $LOGFILE

if [ $? != 0 ]; then
    date >> $LOGFILE
    echo ++ ERROR >>  $LOGFILE
#    /etc/init.d/fastd restart
else
    date >> $LOGFILE
    echo OK. >> $LOGFILE
fi

echo ---------------------------------------- >> $LOGFILE
