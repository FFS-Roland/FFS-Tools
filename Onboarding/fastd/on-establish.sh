#!/bin/sh

LOGFILE=/var/freifunk/logs/vpn00_established.log

date >> $LOGFILE

while :
do
    ONBOARDINGPID=$(ps -e | grep "ffs-Onboarding" | cut -d " " -s -f1 | head -n1)
    if [ "$ONBOARDINGPID" != "" ]; then
        kill $ONBOARDINGPID
        echo ++ Killed still running ffs-Onboarding Process $ONBOARDINGPID >> $LOGFILE
        sleep 1
    else
        break
    fi
done

echo Starting new ffs-Onboarding Process ... >> $LOGFILE

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
