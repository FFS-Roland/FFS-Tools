#!/bin/sh

###########################################################################################
#                                                                                         #
#  on-establis.sh                                                                         #
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
#  Copyright (c) 2017, Roland Volkmann <roland.volkmann@t-online.de>                      #
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

LOGFILE=/var/freifunk/logs/vpnWW_established.log


#----- Path Definitions -----
BLACKLIST=/var/freifunk/blacklist
PEERGITREPO=/var/freifunk/peers-ffs
JSONDATA=/var/freifunk/json


date >> $LOGFILE
echo Starting new ffs-Onboarding Process ... >> $LOGFILE

/usr/local/bin/ffs-Onboarding.py --pid $FASTD_PID --fastd $INTERFACE --batman batWW --peerkey $PEER_KEY --gitrepo $PEERGITREPO --json $JSONDATA --blacklist $BLACKLIST >> $LOGFILE

if [ $? != 0 ]; then
  date >> $LOGFILE
  echo ++ ERROR >> $LOGFILE
  kill -SIGUSR2 $FASTD_PID    # drop all connections
  kill -SIGCHLD $FASTD_PID    # unlink zombies
else
  date >> $LOGFILE
  echo OK. >> $LOGFILE
fi

echo ---------------------------------------- >> $LOGFILE
