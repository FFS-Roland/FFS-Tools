#!/bin/sh

LOGFILE=/var/freifunk/logs/vpn00_verify.log

date >> $LOGFILE
echo $PEER_KEY >> $LOGFILE

if [ -f /etc/fastd/$INTERFACE/blacklist/$PEER_KEY ]; then
  LOCKTIME=`cat /etc/fastd/$INTERFACE/blacklist/$PEER_KEY`
  NOW=`date +%s`
  DELTA=$((NOW - LOCKTIME))
  if [ $DELTA -gt 600 ]; then
    rm /etc/fastd/$INTERFACE/blacklist/$PEER_KEY
    echo Blocking removed. >> $LOGFILE
  else
    echo Node is blacklisted. >> $LOGFILE
    echo --------------------- >> $LOGFILE
    exit 1
  fi
fi

echo OK >> $LOGFILE
exit 0
