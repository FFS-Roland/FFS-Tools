#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  ffs-Monitoring.py                                                                      #
#                                                                                         #
#  Segment-Assignment of Nodes is monitored and corrected automatically if neccessary.    #
#                                                                                         #
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
import urllib.request
import time
import datetime
import json
import re
import hashlib

from class_ffGatewayInfo import *
from class_ffNodeInfo import *
from class_ffMeshNet import *



#-------------------------------------------------------------
# Local Paths
#-------------------------------------------------------------

PeerRepositoryDir = '/var/freifunk/peers-ffs/'

MacTableFileName  = '/var/freifunk/logs/MacTable.txt'
MeshCloudListFile = '/var/freifunk/logs/Neighbors.txt'
NodeMoveFileName  = '/var/freifunk/logs/NodeMoves.txt'


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
print('Step 1 = Setup ...')

ffsNodes = ffNodeInfo(AlfredURL,RawJsonAccess)
ffsGWs   = ffGatewayInfo(PeerRepositoryDir)
ffsNet   = ffMeshNet(ffsNodes,ffsGWs)


print('Merging Data from GW-Infos to Node-Infos  ...')

ffsNet.MergeData()

ffsNodes.DumpMacTable(MacTableFileName)


print('\nCheck Segments ...')

ffsNet.CheckSegments()

ffsNet.WriteMeshCloudList(MeshCloudListFile)
ffsNet.WriteMoveList(NodeMoveFileName)


print('OK.\n')

