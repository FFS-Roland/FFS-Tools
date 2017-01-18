#!/bin/sh

date >> /var/freifunk/logs/checkedkey
echo $PEER_KEY >> /var/freifunk/logs/checkedkey 

if [ -f /etc/fastd/$INTERFACE/blacklist/$PEER_KEY ]; then
  LOCKTIME=`cat /etc/fastd/$INTERFACE/blacklist/$PEER_KEY`
  NOW=`date +%s`
  DELTA=$((NOW - LOCKTIME))
  if [ $DELTA -gt 300 ]; then
    rm /etc/fastd/$INTERFACE/blacklist/$PEER_KEY
  else
    date >> /var/freifunk/logs/checkedkey
    echo Blacklisted >> /var/freifunk/logs/checkedkey
    exit 1
  fi
fi

date >> /var/freifunk/logs/checkedkey
echo OK >> /var/freifunk/logs/checkedkey
exit 0
