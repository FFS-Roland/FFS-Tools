#!/bin/bash

###########################################################################################
#                                                                                         #
#  fastd-on-establis.sh                                                                   #
#                                                                                         #
#  This shell script is launched by fastd whenever a new connection is established.       #
#  It will run python script "ffs-Onboarding.py" to handle unknown peers.                 #
#                                                                                         #
#  Available Environment Variables from fastd:                                            #
#                                                                                         #
#      $FASTD_PID  = PID of fastd Process launching this script                           #
#      $INTERFACE  = fastd-Interface (e.g. vpn00)                                         #
#      $PEER_KEY   = fastd-Key of Peer which is connected                                 #
#                                                                                         #
###########################################################################################

LOGDIR=/var/log/ffs/onboarder
LOGFILE=${LOGDIR}/${INTERFACE}_$(date +%y%m%d)_established.log


#----- Path Definitions -----
PEERGITREPO=/var/lib/ffs/git/peers-ffs
DATAPATH=/var/lib/ffs/database
BLACKLIST=/var/lib/ffs/blacklist


date >> $LOGFILE

echo Starting new ffs-Onboarding Process on $INTERFACE from $PEER_ADDRESS ... >> $LOGFILE

/usr/local/bin/ffs-Onboarding.py --fastd $INTERFACE --mtu $INTERFACE_MTU --batman bat${INTERFACE:3:5} --pid $FASTD_PID --peerkey $PEER_KEY --gitrepo $PEERGITREPO --data $DATAPATH --blacklist $BLACKLIST >> $LOGFILE

if [ $? != 0 ]; then
    date >> $LOGFILE
    echo ++ ERROR >> $LOGFILE
    kill -s 12 $FASTD_PID    # SIGUSR2 = drop all connections
    kill -s 17 $FASTD_PID    # SIGCHLD = unlink zombies
else
    date >> $LOGFILE
    echo OK. >> $LOGFILE
fi

echo ------------------------------------------------------------- >> $LOGFILE


#----- Removing old Logs -----
for Log in $(ls -r ${LOGDIR}/${INTERFACE}_??????_established.log | tail -n +4);
do
    rm $Log
done
