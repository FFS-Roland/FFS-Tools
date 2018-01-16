#!/bin/sh

###########################################################################################
#                                                                                         #
#  ffs-Check.sh                                                                           #
#                                                                                         #
#  This shell script is launched by cron to check Freifunk infrastructure.                #
#  The check itself is done by python script "ffs-Monitoring.py", providing a shell       #
#  script for automatic Git moves with commit and push in case of nodes are in wrong      #
#  segment.                                                                               #
#                                                                                         #
###########################################################################################
#                                                                                         #
#  Copyright (c) 2017-2018, Roland Volkmann <roland.volkmann@t-online.de>                 #
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

#exit 0

GITREPO=/var/freifunk/peers-ffs
DATADIR=/var/freifunk/database
ALFRED=http://netinfo.freifunk-stuttgart.de/json/

LOGDIR=/var/freifunk/logs
LOGFILE=$LOGDIR/$(date +%s).log
OLDLOGS=$LOGDIR/1*.log


date > $LOGFILE

#----- Removing Log Files older than 24 Hours -----
NOW=$(date +%s)

for Log in $(ls $OLDLOGS | sed "s!$LOGDIR/!!g");
do
    LOGTIME=$(echo $Log | cut -d'.' -f1)
    DELTA=$((NOW - LOGTIME))

    if [ $DELTA -gt 86400 ]; then
        rm $LOGDIR/$Log
    fi
done


#----- start Monitoring -----

if [ $(ps -e | grep -c "ffs-Monitoring") -gt 0 ]; then
  echo ++ Still running ffs-Monitoring Process >> $LOGFILE
  exit 1
fi

/usr/local/bin/ffs-Monitoring.py --gitrepo=$GITREPO --data=$DATADIR --alfred=$ALFRED --logs=$LOGDIR >> $LOGFILE

if [ $? -ne 0 ]; then
  echo "++ERROR!" >> $LOGFILE
fi

date >> $LOGFILE
