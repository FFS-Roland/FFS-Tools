#!/bin/bash

###########################################################################################
#                                                                                         #
#  fastd-on-verify.sh                                                                     #
#                                                                                         #
#  This shell script is launched by fastd whenever a peer requests a connection which     #
#  must be checked for beeing allowed.                                                    #
#                                                                                         #
#  Exit Code 0 = Request accepted                                                         #
#            1 = Request denied because of blacklisting or other instance still running.  #
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

#exit 1    # for blocking during test phase only - will be removed later!


#----- Path Definitions -----
LOGDIR=/var/log/ffs/onboarder
LOGFILE=${LOGDIR}/$(date +%y%m%d)_verify.log

BLACKLIST=/var/lib/ffs/blacklist



date >> $LOGFILE
echo $PEER_KEY >> $LOGFILE
echo $INTERFACE / $PEER_ADDRESS >> $LOGFILE

if [ $(ps -x | grep -v "grep" |  grep -c "ffs-Onboarding.py --fastd $INTERFACE") -gt 0 ]; then
  echo ++ Another ffs-Onboarding Process is still running >> $LOGFILE
  echo --------------------- >> $LOGFILE
  exit 1
fi

if [ -f $BLACKLIST/$PEER_KEY ]; then
  LOCKTIME=$(cat $BLACKLIST/$PEER_KEY)
  NOW=$(date +%s)
  DELTA=$((NOW - LOCKTIME))
  if [ $DELTA -gt 600 ]; then
    rm $BLACKLIST/$PEER_KEY
    echo Blocking removed. >> $LOGFILE
  else
    echo Node is blacklisted. >> $LOGFILE
    echo --------------------- >> $LOGFILE
    exit 1
  fi
fi

echo OK >> $LOGFILE
echo --------------------- >> $LOGFILE


#----- Removing old Logs -----
for Log in $(ls -r ${LOGDIR}/??????_verify.log | tail -n +4);
do
  rm $Log
done

exit 0
