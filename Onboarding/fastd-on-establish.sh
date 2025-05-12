#!/bin/bash

#################################################################################################
#                                                                                               #
#   fastd-on-establis.sh                                                                        #
#                                                                                               #
#   This shell script is launched by fastd whenever a new connection is established.            #
#   It will run python script "ffs-Onboarding.py" to handle unknown peers.                      #
#                                                                                               #
#   Available Environment Variables from fastd:                                                 #
#                                                                                               #
#       $FASTD_PID  = PID of fastd Process launching this script                                #
#       $INTERFACE  = fastd-Interface (e.g. vpn00)                                              #
#       $PEER_KEY   = fastd-Key of Peer which is connected                                      #
#                                                                                               #
#################################################################################################
#                                                                                               #
#   Copyright (C) 2025  Freifunk Stuttgart e.V.                                                 #
#                                                                                               #
#   This program is free software: you can redistribute it and/or modify it under the terms     #
#   of the GNU General Public License as published by the Free Software Foundation, either      #
#   version 3 of the License, or (at your option) any later version.                            #
#                                                                                               #
#   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;   #
#   without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   #
#   See the GNU General Public License for more details.                                        #
#                                                                                               #
#   You should have received a copy of the GNU General Public License along with this program.  #
#   If not, see <https://www.gnu.org/licenses/>.                                                #
#                                                                                               #
#################################################################################################


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
