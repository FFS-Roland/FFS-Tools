#!/bin/sh

git -C /var/freifunk/peers-ffs pull --rebase=true
echo $?

date > /var/freifunk/logs/monitoring.log
/usr/local/bin/ffs-Monitoring.py --gitrepo /var/freifunk/peers-ffs --logs /var/freifunk/logs --json /var/freifunk/json >> /var/freifunk/logs/monitoring.log
echo $?
