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
#                                                                                         #
#  Copyright (c) 2017-2019, Roland Volkmann <roland.volkmann@t-online.de>                 #
#  All rights reserved.                                                                   #
#                                                                                         #
#  Redistribution and use in source and binary forms, with or without                     #
#  modification, are permitted provided that the following conditions are met:            #
#    1. Redistributions of source code must retain the above copyright notice,            #
#       this list of conditions and the following disclaimer.                             #
#    2. Redistributions in binary form must reproduce the above copyright notice,         #
#       this list of conditions and the following disclaimer in the documentation         #
#       and/or other materials provided with the distribution.                            #
#                                                                                         #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"            #
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE              #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE         #
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE           #
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL             #
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR             #
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER             #
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,          #
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE          #
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                   #
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

echo ---------------------------------------- >> $LOGFILE


#----- Removing old Logs -----
for Log in $(ls -r ${LOGDIR}/${INTERFACE}_??????_established.log | tail -n +4);
do
    rm $Log
done
