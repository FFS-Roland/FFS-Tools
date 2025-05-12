#!/bin/sh

#################################################################################################
#                                                                                               #
#   ffs-Check.sh                                                                                #
#                                                                                               #
#   This shell script is launched by cron to check Freifunk infrastructure.                     #
#   The check itself is done by python script "ffs-Monitoring.py", providing a shell            #
#   script for automatic Git moves with commit and push in case of nodes are in wrong           #
#   segment.                                                                                    #
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

#exit 0


PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

GITREPO=/var/lib/ffs/git/peers-ffs
DATADIR=/var/lib/ffs/database

LOGDIR=/var/log/ffs/monitor
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

/usr/local/bin/ffs-Monitoring.py --gitrepo=$GITREPO --data=$DATADIR --logs=$LOGDIR >> $LOGFILE

if [ $? -ne 0 ]; then
  echo "++ERROR!" >> $LOGFILE
else
  /usr/local/bin/create_StatisticsData.py --nodefile=$DATADIR/NodeDict.json --regions=$DATADIR/Region2ZIP.json --statistics=$DATADIR/StatisticsDict.json >> $LOGFILE
fi

echo "---------------------------------------" >> $LOGFILE
date >> $LOGFILE
