#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  ffs-Monitoring.py                                                                      #
#                                                                                         #
#  Segment-Assignment of Nodes is monitored and corrected automatically if neccessary.    #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#       --gitrepo  = Git Repository with KeyFiles                                         #
#       --logs     = Path to LogFiles                                                     #
#       --json     = Path to json-Files (Databases with fastd-Keys and Statistics)        #
#                                                                                         #
#  Needed json-Files from Webserver:                                                      #
#                                                                                         #
#       raw.json             -> Node Names and Information                                #
#       nodesdb.json         -> Region = Segment                                          #
#       alfred-json-158.json -> Nodeinfos                                                 #
#       alfred-json-159.json -> VPN-Uplinks                                               #
#       alfred-json-160.json -> Neighbors                                                 #
#       fastd-clean.json     -> fastd-Keys (live Data)                                    #
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

import os
import time
import datetime
import argparse

from class_ffGatewayInfo import *
from class_ffNodeInfo import *
from class_ffMeshNet import *



#-------------------------------------------------------------
# LogFile Names
#-------------------------------------------------------------

MacTableFile      = 'MacTable.lst'
MeshCloudListFile = 'MeshClouds.lst'
NodeMoveFile      = 'NodeMoves.lst'


#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

MaxOfflineDays    = 10 * 86400


AlfredURL  = 'http://netinfo.freifunk-stuttgart.de/json/'

RawJsonAccess = {
    'URL':'http://map.freifunk-stuttgart.de/json/raw.json',
    'Username':'freifunk',
    'Password':'json'
    }




#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
parser = argparse.ArgumentParser(description='Check Freifunk Segments')
parser.add_argument('--gitrepo', dest='GITREPO', action='store', required=True, help='Git Repository with KeyFiles')
parser.add_argument('--logs', dest='LOGPATH', action='store', required=True, help='Path to LogFiles')
parser.add_argument('--json', dest='JSONPATH', action='store', required=False, help='optional Path to KeyDatabase')
args = parser.parse_args()


print('Setting up basic data ...')

ffsGWs = ffGatewayInfo(args.GITREPO)

isOK = ffsGWs.VerifyDNS()	# Check DNS against keys from Git

if not args.JSONPATH is None:
    print('Writing Key Databases ...')
    ffsGWs.WriteFastdDB(args.JSONPATH)

ffsNodes = ffNodeInfo(AlfredURL,RawJsonAccess)


print('Setting up Mesh Net Info ...')

ffsNet = ffMeshNet(ffsNodes,ffsGWs)


print('Merging Data from GW-Infos to Node-Infos  ...')

ffsNet.MergeData()

ffsNodes.DumpMacTable(os.path.join(args.LOGPATH,MacTableFile))
ffsNodes.UpdateStatistikDB(args.JSONPATH)


print('\nCheck Segments ...')

ffsNet.CheckSegments()

ffsNet.WriteMeshCloudList(os.path.join(args.LOGPATH,MeshCloudListFile))
ffsNet.WriteMoveList(os.path.join(args.LOGPATH,NodeMoveFile))


print('OK.\n')

