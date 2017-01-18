#!/bin/sh

date >> /var/freifunk/logs/establishedkey
echo start $PEER_KEY >> /var/freifunk/logs/establishedkey

/usr/local/bin/ffs-Onboarding.py --fastd $INTERFACE --batman bat00 --peerkey $PEER_KEY --gitrepo /var/freifunk/peers-ffs --blacklist /etc/fastd/$INTERFACE/blacklist

if [ $? != 0 ]; then
    date >> /var/freifunk/logs/establishedkey
    echo ERROR $PEER_KEY >> /var/freifunk/logs/establishedkey
#    /etc/init.d/fastd restart
else
    date >> /var/freifunk/logs/establishedkey
    echo OK $PEER_KEY >> /var/freifunk/logs/establishedkey
fi
