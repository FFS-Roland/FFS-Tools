#!/bin/sh

git -C /var/freifunk/peers-ffs pull --rebase=true
echo $?

/usr/local/bin/ffs-Monitoring.py --gitrepo /var/freifunk/peers-ffs --logs /var/freifunk/logs > /var/freifunk/logs/monitoring.log
echo $?
