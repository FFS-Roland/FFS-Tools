#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  class_ffMeshNet.py                                                                     #
#                                                                                         #
#  Combining and analysing Data from Nodes and Gateways to find Mesh-Clouds.              #
#                                                                                         #
#                                                                                         #
#  Needed Python Classes:                                                                 #
#                                                                                         #
#      class_ffNodeInfo     -> Node Names and Information                                 #
#      class_ffGatewayInfo  -> Keys and Segment Information                               #
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

import os
import subprocess
import time
import datetime
import fcntl
import re

from class_ffNodeInfo import *
from class_ffGatewayInfo import *



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

StatFileName   = 'SegStatistics.json'

MaxStatisticsData  = 12 * 24 * 7    # 1 Week wit Data all 5 Minutes

GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[1-9]))(:[0-9a-f]{2}){3}')

NODETYPE_UNKNOWN       = 0
NODETYPE_LEGACY        = 1
NODETYPE_SEGMENT_LIST  = 2
NODETYPE_DNS_SEGASSIGN = 3
NODETYPE_MTU_1340      = 4

NODESTATE_UNKNOWN      = '?'
NODESTATE_OFFLINE      = '#'
NODESTATE_ONLINE_MESH  = ' '
NODESTATE_ONLINE_VPN   = 'V'

NODEWEIGHT_OFFLINE     = 1
NODEWEIGHT_MESH_ONLY   = 3
NODEWEIGHT_UPLINK      = 1000
NODEWEIGHT_SEGMENT_FIX = 1000000

CPE_TEMP_SEGMENT       = 23



class ffMeshNet:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,NodeInfos,GwInfos):

        # public Attributes
        self.Alerts          = []       # List of  Alert-Messages
        self.AnalyseOnly     = False    # Blocking active Actions due to inkonsistent Data

        # private Attributes
        self.__NodeInfos = NodeInfos
        self.__GwInfos   = GwInfos

        self.__MeshCloudDict  = {}      # Dictionary of Mesh-Clouds with List of Member-Nodes
        self.__SegmentDict    = {}      # Segment Data: { 'Nodes','Clients','Uplinks' }
        self.__NodeMoveDict   = {}      # Git Moves of Nodes from one Segment to another

        # Initializations
        self.__CheckConsistency()
        self.__CreateMeshCloudList()
        self.__CheckMeshClouds()
        self.__CheckSingleNodes()
        return



    #-----------------------------------------------------------------------
    # private function "__alert"
    #
    #   Store and print Message for Alert
    #
    #-----------------------------------------------------------------------
    def __alert(self,Message):

        self.Alerts.append(Message)
        print(Message)
        return



    #-----------------------------------------------------------------------
    # private function "__AddNeighbour2Cloud"
    #
    #   Add Nodes to Mesh-Cloud-List (recursive)
    #
    # MeshCloudDict[CloudID] -> List of Nodes in Mesh-Cloud
    #-----------------------------------------------------------------------
    def __AddNeighbour2Cloud(self,CloudID,ffNeighbourMAC):

        if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Status'] != NODESTATE_UNKNOWN and ffNeighbourMAC not in self.__MeshCloudDict[CloudID]['CloudMembers']:

            if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] is None:
                self.__MeshCloudDict[CloudID]['NumClients'] += self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Clients']
                self.__MeshCloudDict[CloudID]['CloudMembers'].append(ffNeighbourMAC)
                self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] = CloudID

                if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['GluonType'] < self.__MeshCloudDict[CloudID]['GluonType'] and self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    self.__MeshCloudDict[CloudID]['GluonType'] = self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['GluonType']

                for MeshMAC in self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Neighbours']:
                    if MeshMAC in self.__NodeInfos.MAC2NodeIDDict:
                        self.__AddNeighbour2Cloud(CloudID,self.__NodeInfos.MAC2NodeIDDict[MeshMAC])
                    else:
                        print('!! Unknown Neighbour: %02d - %s = \'%s\' -> %s' % (
                            self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Segment'],ffNeighbourMAC,self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name'],MeshMAC))
            elif self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] == CloudID:
                print('!! Cloud inconsistent:',CloudID,'-',ffNeighbourMAC,'= \''+self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name']+'\' ->',self.__MeshCloudDict[CloudID]['CloudMembers'])
            else:
                # Node is already part of another Mesh Cloud -> merge Clouds ...
                oldCloudID = self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud']

                self.__MeshCloudDict[CloudID]['NumClients']   += self.__MeshCloudDict[oldCloudID]['NumClients']
                self.__MeshCloudDict[CloudID]['CloudMembers'] += self.__MeshCloudDict[oldCloudID]['CloudMembers']

                if self.__MeshCloudDict[oldCloudID]['GluonType'] < self.__MeshCloudDict[CloudID]['GluonType']:
                    self.__MeshCloudDict[CloudID]['GluonType'] = self.__MeshCloudDict[oldCloudID]['GluonType']

                for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] == oldCloudID:
                        self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] = CloudID

                del self.__MeshCloudDict[oldCloudID]

        return



    #-----------------------------------------------------------------------
    # private function "__CreateMeshCloudList"
    #
    #   Create Mesh-Cloud-List
    #
    # MeshCloudDict[CloudID] -> List of Nodes in Mesh-Cloud
    #-----------------------------------------------------------------------
    def __CreateMeshCloudList(self):

        print('\nCreate Mesh Cloud List ...')
        TotalNodes = 0
        TotalClients = 0

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN and self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] is None) and
                (len(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Neighbours']) > 0)):

                self.__MeshCloudDict[ffNodeMAC] = {
                    'NumClients': 0,
                    'GluonType': 99,
                    'CloudMembers': [],
                    'CloudSegment': None
                }

                self.__AddNeighbour2Cloud(ffNodeMAC,ffNodeMAC)

                if len(self.__MeshCloudDict[ffNodeMAC]['CloudMembers']) < 2:
                    print('++ Single-Node Cloud: %02d - %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] = None
                    del self.__MeshCloudDict[ffNodeMAC]
                else:
                    TotalNodes   += len(self.__MeshCloudDict[ffNodeMAC]['CloudMembers'])
                    TotalClients += self.__MeshCloudDict[ffNodeMAC]['NumClients']

        print('... Number of Clouds / Nodes / Clients:',len(self.__MeshCloudDict),'/',TotalNodes,'/',TotalClients)
        print()
        return



    #-----------------------------------------------------------------------
    # private function "__MarkNodesInCloudForMove"
    #
    #   Move Nodes of Meshcloud to other Segement
    #
    #-----------------------------------------------------------------------
    def __MarkNodesInCloudForMove(self,CloudID,TargetSeg):

        for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
            if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                    if ffNodeMAC in self.__NodeMoveDict:
                        print('!! Multiple Move: %s -> %s' % (ffNodeMAC,TargetSeg))

                    if TargetSeg == 0:
                        print('!! No move to Legacy: %s/peers/%s\n' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']) )
                    else:
                        self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                        print('>> git mv %s/peers/%s vpn%02d/peers/  = \'%s\'\n' % ( self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                                 TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'] ))
        return



    #-----------------------------------------------------------------------
    # private function "__CheckMeshClouds"
    #
    #   Analysing Mesh Clouds for Segment Shortcuts and set common Segment
    #
    #-----------------------------------------------------------------------
    def __CheckMeshClouds(self):

        print('Checking Mesh-Clouds ...')

        for CloudID in self.__MeshCloudDict:
            DesiredSegDict = {}    # Weight of Nodes per desired Segments
            CurrentSegList = []    # List of current Segments of the Nodes
            UpLinkSegDict  = {}    # Weight of UpLink-Nodes per Segment
            UpTimeSegDict  = {}    # max. UpTime of Uplink-Nodes per Segment

            #---------- Analysing nodes and related desired segments ----------
            for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
                NodeSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']

                if NodeSeg not in CurrentSegList:
                    CurrentSegList.append(NodeSeg)

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    else:
                        NodeWeigt = NODEWEIGHT_UPLINK

                    if NodeSeg not in UpLinkSegDict:
                        UpLinkSegDict[NodeSeg] = NodeWeigt
                    else:
                        UpLinkSegDict[NodeSeg] += NodeWeigt

                    if NodeSeg not in UpTimeSegDict:
                        UpTimeSegDict[NodeSeg] = 0.0

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Uptime'] > UpTimeSegDict[NodeSeg]:
                        UpTimeSegDict[NodeSeg] = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Uptime']

                else:
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_MESH:
                        NodeWeigt = NODEWEIGHT_MESH_ONLY
                    else:
                        NodeWeigt = NODEWEIGHT_OFFLINE

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] is not None:
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] not in DesiredSegDict:
                        DesiredSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']] = NodeWeigt
                    else:
                        DesiredSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']] += NodeWeigt

            if len(UpLinkSegDict) == 0:
                print('++ Cloud seems to be w/o VPN Uplink(s):',self.__MeshCloudDict[CloudID]['CloudMembers'])
                SearchList = CurrentSegList

                for Segment in DesiredSegDict:
                    if Segment not in SearchList:
                        SearchList.append(Segment)

                for ffNodeMAC in self.__NodeInfos.GetUplinkList(self.__MeshCloudDict[CloudID]['CloudMembers'],SearchList):
                    NodeSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']
                    print('>> Uplink found by Batman: Seg.%02d - %s = \'%s\'' % (NodeSeg,ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    else:
                        NodeWeigt = NODEWEIGHT_UPLINK

                    if NodeSeg not in UpLinkSegDict:
                        UpLinkSegDict[NodeSeg] = NodeWeigt
                    else:
                        UpLinkSegDict[NodeSeg] += NodeWeigt

                    if NodeSeg not in UpTimeSegDict:
                        UpTimeSegDict[NodeSeg] = 0.0

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Uptime'] > UpTimeSegDict[NodeSeg]:
                        UpTimeSegDict[NodeSeg] = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Uptime']

            #---------- Calculating desired Segment for the Cloud ----------
            CloudSegment = None
            SegWeight = 0

            for Segment in DesiredSegDict:
                if DesiredSegDict[Segment] > SegWeight or (DesiredSegDict[Segment] == SegWeight and UpTimeSegDict[Segment] > UpTimeSegDict[CloudSegment]):
                    CloudSegment = Segment
                    SegWeight = DesiredSegDict[Segment]

            if CloudSegment is None:
                for Segment in UpLinkSegDict:
                    if UpLinkSegDict[Segment] > SegWeight or (UpLinkSegDict[Segment] == SegWeight and UpTimeSegDict[Segment] > UpTimeSegDict[CloudSegment]):
                        CloudSegment = Segment
                        SegWeight = UpLinkSegDict[Segment]

            self.__MeshCloudDict[CloudID]['CloudSegment'] = CloudSegment

            #---------- Actions depending of situation in cloud ----------
            if len(UpLinkSegDict) > 1 or len(CurrentSegList) > 1:
                self.__alert('!! Shortcut detected: UplinkSegs = %d / CurrentSegs = %d' % (len(UpLinkSegDict),len(CurrentSegList)))

                if CloudSegment is None:
                    self.__alert('!! Shortcut cannot be corrected, missing CloudSegment !!')
                    self.AnalyseOnly = True
                else:
                    self.__alert('** Shortcut will be corrected ...')
                    print(self.__MeshCloudDict[CloudID]['CloudMembers'])
                    print()

            if CloudSegment is not None:
                self.__MarkNodesInCloudForMove(CloudID,CloudSegment)

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__CheckSingleNodes"
    #
    #   Check if Node is in correct Segment
    #
    #-----------------------------------------------------------------------
    def __CheckSingleNodes(self):

        print('Checking Single Nodes ...')

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] is None and self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN) and
                (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][:3] == 'vpn')):

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_MESH:
                    print('++ Node seems to be w/o VPN Uplink: %s / %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))

                    for UplinkNodeMAC in self.__NodeInfos.GetUplinkList([ffNodeMAC],[int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])]):
                        self.__NodeInfos.ffNodeDict[UplinkNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                        print('>> Uplink found by Batman:',UplinkNodeMAC)

                TargetSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']

                if TargetSeg is not None:
                    if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                        if TargetSeg <= 8 or self.__NodeInfos.ffNodeDict[ffNodeMAC]['GluonType'] >= NODETYPE_DNS_SEGASSIGN:
                            if ffNodeMAC in self.__NodeMoveDict:
                                print('!! Multiple Move:',ffNodeMAC,'->',TargetSeg)

                            self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                            print('>> git mv %s/peers/%s vpn%02d/peers/  = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                                      TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'] ))
                        else:
                            print('!! Gluon too old for desired Segment: %s = \'%s\' -> Seg. %02d' % (ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'],TargetSeg))

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "CheckConsistency"
    #
    #
    #-----------------------------------------------------------------------
    def __CheckConsistency(self):

        print('Checking Consistency of Data ...')
        SegmentList = self.__GwInfos.GetSegmentList()

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN:

                if (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Hardware'].lower().startswith('tp-link cpe') and
                    (self.__NodeInfos.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_MTU_1340 or self.__NodeInfos.ffNodeDict[ffNodeMAC]['Firmware'][:14] < '1.4+2018-06-24')):
                    print('++ Old CPE found: %s %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] = CPE_TEMP_SEGMENT
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'] = 'fix %02d' % (CPE_TEMP_SEGMENT)

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == '':
                        print('!! Uplink w/o Key: %s %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))
                        self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH
                    elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] != int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]):
                        print('!! Segment <> KeyDir: %s %s = \'%s\': Seg.%02d <> %s' % (
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'],
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir']))
                else:
                    for NeighbourMAC in self.__NodeInfos.ffNodeDict[ffNodeMAC]['Neighbours']:
                        if GwAllMacTemplate.match(NeighbourMAC):
                            print('!! GW-Connection w/o Uplink: %s %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] is not None:
                    if (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != ''
                    and self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])
                    and self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'] == 'auto'):
                        print('++ Wrong Segment:   %s %s = \'%s\': %02d -> %02d %s' % (
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'],int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]),
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode']))

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] > 8 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_DNS_SEGASSIGN:
                        print('!! Invalid Segment for Gluon-Type %d: >%s< %s = \'%s\' -> Seg. %02d' % (
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['GluonType'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'],
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']))
                    elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] == 0:
                        print('!! Legacy Node found: %s %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))
                        self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_UNKNOWN    # ignore this Node Data

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'] != '':
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].strip().lower() != self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].strip().lower():
                        print('++ Hostname Mismatch:  %s = \'%s\' <- \'%s\'' % (
                            self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'],
                            self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName']))

                if self.__NodeInfos.IsOnline(ffNodeMAC):
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is None:
                        print('!! Segment is None: %s %s = \'%s\'' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name']))
                        self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_UNKNOWN    # ignore this Node Data
                    elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] not in SegmentList:
                        print('>>> Bad Segment:   %s %s = \'%s\' in Seg.%02d' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']))
                        self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_UNKNOWN    # ignore this Node Data

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "CalcSegmentStatistics"
    #
    #
    #-----------------------------------------------------------------------
    def __CalcSegmentStatistics(self):

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if self.__NodeInfos.IsOnline(ffNodeMAC):
                ffSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']

                if ffSeg not in self.__SegmentDict:
                    self.__SegmentDict[ffSeg] = { 'Nodes':0, 'Clients':0, 'Uplinks':0 }

                self.__SegmentDict[ffSeg]['Nodes'] += 1
                self.__SegmentDict[ffSeg]['Clients'] += self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    self.__SegmentDict[ffSeg]['Uplinks'] += 1

        return



    #==============================================================================
    # Method "GetMoveDict"
    #
    #   returns NodeMoveDict if there are nodes to be moved
    #
    #==============================================================================
    def GetMoveDict(self):

        if len(self.__NodeMoveDict) > 0:
            MoveData = self.__NodeMoveDict
        else:
            MoveData = None

        return MoveData



    #==============================================================================
    # Method "WriteMeshCloudList"
    #
    #   Write out Mesh Cloud List
    #==============================================================================
    def WriteMeshCloudList(self,FileName):

        print('Writing out Mesh Cloud List ...')

        MeshCloudFile = open(FileName, mode='w')
        MeshCloudFile.write('FFS-Mesh-Clouds on %s\n' % datetime.datetime.now())

        RegionDict = {}
        GluonMarker = [ '?', '%', '$', '$', ' ' ]
        TotalMeshingNodes = 0

        for CloudID in sorted(self.__MeshCloudDict):

            TotalNodes    = 0
            TotalClients  = 0
            TotalUplinks  = 0
            OldGluon      = 0
            CurrentSeg    = self.__MeshCloudDict[CloudID]['CloudSegment']
            CurrentVPN    = None
            CurrentRegion = None
            CurrentZIP    = None
            CurrentError  = ''

            MeshCloudFile.write('\n------------------------------------------------------------------------------------------------------------------\n')
            TotalMeshingNodes += len(self.__MeshCloudDict[CloudID]['CloudMembers'])

            for ffnb in sorted(self.__MeshCloudDict[CloudID]['CloudMembers']):
                CurrentError = ' '

                if self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeInfos.ffNodeDict[ffnb]['Segment']

                    if CurrentSeg is None:
                        print('++ ERROR CloudSegment is None -> Setting Seg. %02d !!' % (Segment))
                        CurrentSeg = Segment
                    elif Segment != CurrentSeg:
#                        print('++ ERROR Segment:',ffnb,'=',CurrentSeg,'<>',Segment)
                        CurrentError = '!'

                    if CurrentRegion is None or CurrentRegion == '??':
                        CurrentRegion = self.__NodeInfos.ffNodeDict[ffnb]['Region']
                    elif self.__NodeInfos.ffNodeDict[ffnb]['Region'] != '??' and self.__NodeInfos.ffNodeDict[ffnb]['Region'] != CurrentRegion:
                        print('++ ERROR Region:',ffnb,'= \''+self.__NodeInfos.ffNodeDict[ffnb]['Name']+'\' ->',self.__NodeInfos.ffNodeDict[ffnb]['Region'],'<>',CurrentRegion)
                        CurrentError = '!'

                    if CurrentZIP is None:
                        CurrentZIP = self.__NodeInfos.ffNodeDict[ffnb]['ZIP']

                if CurrentError == ' ' and self.__NodeInfos.ffNodeDict[ffnb]['SegMode'] != 'auto':
                    CurrentError = '+'

                if CurrentError == ' ' and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':
                    if ((self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is not None and int(self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffnb]['Segment']) or
                        (self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] is not None and self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != self.__NodeInfos.ffNodeDict[ffnb]['Segment'])):
                        print('++ ERROR Region:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,'= \''+self.__NodeInfos.ffNodeDict[ffnb]['Name']+'\' ->',
                              self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],self.__NodeInfos.ffNodeDict[ffnb]['Segment'],'->',
                              self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],self.__NodeInfos.ffNodeDict[ffnb]['SegMode'])
                        CurrentError = '>'

                if CurrentVPN is None and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':
                    CurrentVPN = self.__NodeInfos.ffNodeDict[ffnb]['KeyDir']
                elif CurrentVPN is not None and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '' and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != CurrentVPN:
                    print('++ ERROR KeyDir:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,'=',CurrentVPN,'<>',self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'])
                    CurrentError = '*'

                if CurrentError == ' ':
                    CurrentError = GluonMarker[self.__NodeInfos.ffNodeDict[ffnb]['GluonType']]

                MeshCloudFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = \'%s\' (%s = %s) UpT = %d\n' % (CurrentError, self.__NodeInfos.ffNodeDict[ffnb]['Status'], Segment,
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Clients'], ffnb, self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['KeyFile'], self.__NodeInfos.ffNodeDict[ffnb]['Name'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'], self.__NodeInfos.ffNodeDict[ffnb]['Region'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Uptime']))
                if self.__NodeInfos.IsOnline(ffnb):
                    TotalNodes   += 1
                    TotalClients += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                if self.__NodeInfos.ffNodeDict[ffnb]['Status'] == NODESTATE_ONLINE_VPN:
                    TotalUplinks += 1

                if self.__NodeInfos.ffNodeDict[ffnb]['GluonType'] < NODETYPE_MTU_1340:
                    OldGluon += 1

            MeshCloudFile.write('\n          Total Online-Nodes / Clients / Uplinks = %3d / %3d / %3d   (Seg. %02d)\n' % (TotalNodes,TotalClients,TotalUplinks,CurrentSeg))

            for ffnb in self.__MeshCloudDict[CloudID]['CloudMembers']:
                self.__NodeInfos.ffNodeDict[ffnb]['Segment'] = CurrentSeg
                self.__NodeInfos.ffNodeDict[ffnb]['Region']  = CurrentRegion
                self.__NodeInfos.ffNodeDict[ffnb]['ZIP']     = CurrentZIP

            if CurrentRegion is None:
                CurrentRegion = '***'

            if CurrentRegion not in RegionDict:
                RegionDict[CurrentRegion] = { 'Nodes':TotalNodes, 'Clients':TotalClients, 'OldGluon':OldGluon, 'Segment':CurrentSeg }
            else:
                RegionDict[CurrentRegion]['Nodes']    += TotalNodes
                RegionDict[CurrentRegion]['Clients']  += TotalClients
                RegionDict[CurrentRegion]['OldGluon'] += OldGluon

        print('\nSum: %d Clouds with %d Nodes\n' % (len(self.__MeshCloudDict),TotalMeshingNodes))
        MeshCloudFile.write('\nSum: %d Clouds with %d Nodes\n' % (len(self.__MeshCloudDict),TotalMeshingNodes))

        print('\nWriting out Single Nodes ...')

        MeshCloudFile.write('\n\n########################################################################\n\n')
        MeshCloudFile.write('Single Nodes:\n\n')

        for ffnb in sorted(self.__NodeInfos.ffNodeDict.keys()):
            if self.__NodeInfos.ffNodeDict[ffnb]['InCloud'] is None and self.__NodeInfos.IsOnline(ffnb) and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':

                CurrentError = ' '

                if self.__NodeInfos.ffNodeDict[ffnb]['SegMode'] != 'auto':
                    CurrentError = '+'

                elif self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] is not None and self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != int(self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'][3:]):
                    print('++ ERROR Region:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],
                          self.__NodeInfos.ffNodeDict[ffnb]['Segment'],'->',self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],self.__NodeInfos.ffNodeDict[ffnb]['SegMode'])

                    CurrentError = '>'

                if self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeInfos.ffNodeDict[ffnb]['Segment']

                if CurrentError == ' ':
                    CurrentError = GluonMarker[self.__NodeInfos.ffNodeDict[ffnb]['GluonType']]

                MeshCloudFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = \'%s\' (%s = %s) UpT = %d\n' % (CurrentError, self.__NodeInfos.ffNodeDict[ffnb]['Status'],
                                                                                                Segment,self.__NodeInfos.ffNodeDict[ffnb]['Clients'], ffnb,
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'], self.__NodeInfos.ffNodeDict[ffnb]['KeyFile'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Name'], self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Region'], self.__NodeInfos.ffNodeDict[ffnb]['Uptime']))
                TotalNodes   += 1
                TotalClients += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                Region = self.__NodeInfos.ffNodeDict[ffnb]['Region']

                if Region not in RegionDict:
                    RegionDict[Region] = { 'Nodes':1, 'Clients':self.__NodeInfos.ffNodeDict[ffnb]['Clients'], 'OldGluon':0, 'Segment':self.__NodeInfos.ffNodeDict[ffnb]['Segment'] }
                else:
                    RegionDict[Region]['Nodes']   += 1
                    RegionDict[Region]['Clients'] += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                if self.__NodeInfos.ffNodeDict[ffnb]['GluonType'] < NODETYPE_MTU_1340:
                    RegionDict[Region]['OldGluon'] += 1


        print('\nCalculating Segment Statistics ...')
        self.__CalcSegmentStatistics()

        print('\nWrite out Statistics ...')

        MeshCloudFile.write('\n\n########################################################################\n\n')
        MeshCloudFile.write('Online-Nodes      / Clients / Sum:\n\n')

        TotalNodes   = 0
        TotalClients = 0
        TotalUplinks = 0

        for ffSeg in sorted(self.__SegmentDict):
            MeshCloudFile.write('Segment %02d: %5d / %5d / %5d\n' % (ffSeg, self.__SegmentDict[ffSeg]['Nodes'], self.__SegmentDict[ffSeg]['Clients'], self.__SegmentDict[ffSeg]['Nodes']+self.__SegmentDict[ffSeg]['Clients']))
            TotalNodes   += self.__SegmentDict[ffSeg]['Nodes']
            TotalClients += self.__SegmentDict[ffSeg]['Clients']
#            TotalUplinks += self.__SegmentDict[ffSeg]['Uplinks']


        MeshCloudFile.write('\n------------------------------------------------------------------------\n')
        MeshCloudFile.write('Totals:     %5d / %5d / %5d\n' % (TotalNodes, TotalClients, TotalNodes+TotalClients))


        MeshCloudFile.write('\n\n########################################################################\n\n')
        MeshCloudFile.write('Stress of Regions:\n\n')

        TotalNodes   = 0
        TotalClients = 0

        for Region in sorted(RegionDict):
            MeshCloudFile.write('%-32s: %4d + %4d = %4d  (Seg.%02d / old = %2d)\n' % (Region, RegionDict[Region]['Nodes'], RegionDict[Region]['Clients'], RegionDict[Region]['Nodes']+RegionDict[Region]['Clients'], RegionDict[Region]['Segment'], RegionDict[Region]['OldGluon']))
            TotalNodes   += RegionDict[Region]['Nodes']
            TotalClients += RegionDict[Region]['Clients']

        MeshCloudFile.write('\n------------------------------------------------------------------------\n')
        MeshCloudFile.write('Totals:     %5d / %5d / %5d\n' % (TotalNodes, TotalClients, TotalNodes+TotalClients))

        MeshCloudFile.close()
        print()
        return
