#!/bin/bash

#################################################################################################
#                                                                                               #
#   fastd-on-verify.sh                                                                          #
#                                                                                               #
#   This shell script is launched by fastd whenever a peer requests a connection which          #
#   must be checked for beeing allowed.                                                         #
#                                                                                               #
#   Exit Code 0 = Request accepted                                                              #
#             1 = Request denied because of blacklisting or other instance still running.       #
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
