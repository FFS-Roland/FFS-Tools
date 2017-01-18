#!/bin/sh

git -C /var/freifunk/peers-ffs pull
echo $?

/usr/local/bin/ffs-Monitoring.py > /var/freifunk/logs/monitoring.log
echo $?
