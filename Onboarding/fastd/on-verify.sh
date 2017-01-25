#!/bin/sh

LOGFILE=/var/freifunk/logs/vpn00_verify.log

date >> $LOGFILE
echo $PEER_KEY >>  $LOGFILE

if [ -f /etc/fastd/$INTERFACE/blacklist/$PEER_KEY ]; then
  LOCKTIME=`cat /etc/fastd/$INTERFACE/blacklist/$PEER_KEY`
  NOW=`date +%s`
  DELTA=$((NOW - LOCKTIME))
  if [ $DELTA -gt 300 ]; then
    rm /etc/fastd/$INTERFACE/blacklist/$PEER_KEY
  else
    date >>  $LOGFILE
    echo Blacklisted >>  $LOGFILE
    exit 1
  fi
fi

date >>  $LOGFILE
echo OK >>  $LOGFILE
exit 0
