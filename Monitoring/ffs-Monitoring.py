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
#       --keydb    = Database with fastd-Keys (json Files)                                #
#                                                                                         #
#  Needed json-Files:                                                                     #
#                                                                                         #
#       raw.json             -> Node Names and Information                                #
#       nodesdb.json         -> Region = Segment                                          #
#       alfred-json-158.json -> Nodeinfos                                                 #
#       alfred-json-159.json -> VPN-Uplinks                                               #
#       alfred-json-160.json -> Neighbors                                                 #
#       fastd-clean.json     -> fastd-Keys (live Data)                                    #
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
parser.add_argument('--keydb', dest='KEYDB', action='store', required=False, help='optional Path to KeyDatabase')
args = parser.parse_args()


print('Setting up basic data ...')

ffsNodes = ffNodeInfo(AlfredURL,RawJsonAccess)
ffsGWs   = ffGatewayInfo(args.GITREPO)

if not args.KEYDB is None:
    print('Writing Key Databases ...')
    ffsGWs.WriteFastdDB(args.KEYDB)


print('Setting up Mesh Net Info ...')

ffsNet   = ffMeshNet(ffsNodes,ffsGWs)


print('Merging Data from GW-Infos to Node-Infos  ...')

ffsNet.MergeData()

ffsNodes.DumpMacTable(os.path.join(args.LOGPATH,MacTableFile))


print('\nCheck Segments ...')

ffsNet.CheckSegments()

ffsNet.WriteMeshCloudList(os.path.join(args.LOGPATH,MeshCloudListFile))
ffsNet.WriteMoveList(os.path.join(args.LOGPATH,NodeMoveFile))


print('OK.\n')

