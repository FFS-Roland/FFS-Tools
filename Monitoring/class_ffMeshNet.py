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
#  Copyright (c) 2017-2020, Roland Volkmann <roland.volkmann@t-online.de>                 #
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

MaxStatisticsData  = 12 * 24 * 7    # 1 Week with Data all 5 Minutes

NODEWEIGHT_OFFLINE     = 1
NODEWEIGHT_MESH_ONLY   = 3
NODEWEIGHT_UPLINK      = 1000
NODEWEIGHT_SEGMENT_FIX = 1000000




class ffMeshNet:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,NodeInfos):

        # public Attributes
        self.Alerts          = []       # List of  Alert-Messages
        self.AnalyseOnly     = False    # Blocking active Actions due to inkonsistent Data

        # private Attributes
        self.__NodeDict       = NodeInfos.ffNodeDict
        self.__MAC2NodeIDDict = NodeInfos.MAC2NodeIDDict

        self.__MeshCloudDict  = {}      # Dictionary of Mesh-Clouds with List of Member-Nodes
        self.__NodeMoveDict   = {}      # Git Moves of Nodes from one Segment to another
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

        if self.__NodeDict[ffNeighbourMAC]['Status'] != NODESTATE_UNKNOWN and ffNeighbourMAC not in self.__MeshCloudDict[CloudID]['CloudMembers']:

            if self.__NodeDict[ffNeighbourMAC]['InCloud'] is None:
                self.__MeshCloudDict[CloudID]['NumClients'] += self.__NodeDict[ffNeighbourMAC]['Clients']
                self.__MeshCloudDict[CloudID]['CloudMembers'].append(ffNeighbourMAC)
                self.__NodeDict[ffNeighbourMAC]['InCloud'] = CloudID

                if self.__NodeDict[ffNeighbourMAC]['GluonType'] < self.__MeshCloudDict[CloudID]['GluonType'] and self.__NodeDict[ffNeighbourMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    self.__MeshCloudDict[CloudID]['GluonType'] = self.__NodeDict[ffNeighbourMAC]['GluonType']

                for MeshMAC in self.__NodeDict[ffNeighbourMAC]['Neighbours']:
                    if MeshMAC in self.__MAC2NodeIDDict:
                        self.__AddNeighbour2Cloud(CloudID,self.__MAC2NodeIDDict[MeshMAC])
                    else:
                        print('!! Unknown Neighbour: %02d - %s = \'%s\' -> %s' % (
                            self.__NodeDict[ffNeighbourMAC]['Segment'],ffNeighbourMAC,self.__NodeDict[ffNeighbourMAC]['Name'],MeshMAC))
            elif self.__NodeDict[ffNeighbourMAC]['InCloud'] == CloudID:
                print('!! Cloud inconsistent:',CloudID,'-',ffNeighbourMAC,'= \''+self.__NodeDict[ffNeighbourMAC]['Name']+'\' ->',self.__MeshCloudDict[CloudID]['CloudMembers'])
            else:
                # Node is already part of another Mesh Cloud -> merge Clouds ...
                oldCloudID = self.__NodeDict[ffNeighbourMAC]['InCloud']

                self.__MeshCloudDict[CloudID]['NumClients']   += self.__MeshCloudDict[oldCloudID]['NumClients']
                self.__MeshCloudDict[CloudID]['CloudMembers'] += self.__MeshCloudDict[oldCloudID]['CloudMembers']

                if self.__MeshCloudDict[oldCloudID]['GluonType'] < self.__MeshCloudDict[CloudID]['GluonType']:
                    self.__MeshCloudDict[CloudID]['GluonType'] = self.__MeshCloudDict[oldCloudID]['GluonType']

                for ffNodeMAC in self.__NodeDict.keys():
                    if self.__NodeDict[ffNodeMAC]['InCloud'] == oldCloudID:
                        self.__NodeDict[ffNodeMAC]['InCloud'] = CloudID

                del self.__MeshCloudDict[oldCloudID]

        return



    #==============================================================================
    # public function "CreateMeshCloudList"
    #
    #   Create Mesh-Cloud-List
    #
    # MeshCloudDict[CloudID] -> List of Nodes in Mesh-Cloud
    #==============================================================================
    def CreateMeshCloudList(self):

        print('\nCreate Mesh Cloud List ...')
        TotalNodes = 0
        TotalClients = 0

        for ffNodeMAC in self.__NodeDict.keys():
            if ((self.__NodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN and self.__NodeDict[ffNodeMAC]['InCloud'] is None) and
                (len(self.__NodeDict[ffNodeMAC]['Neighbours']) > 0)):

                self.__MeshCloudDict[ffNodeMAC] = {
                    'NumClients': 0,
                    'GluonType': 99,
                    'CloudMembers': [],
                    'CloudSegment': None
                }

                self.__AddNeighbour2Cloud(ffNodeMAC,ffNodeMAC)

                if len(self.__MeshCloudDict[ffNodeMAC]['CloudMembers']) < 2:
                    print('++ Single-Node Cloud: %02d - %s = \'%s\'' % (self.__NodeDict[ffNodeMAC]['Segment'],ffNodeMAC,self.__NodeDict[ffNodeMAC]['Name']))
                    self.__NodeDict[ffNodeMAC]['InCloud'] = None
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
            if self.__NodeDict[ffNodeMAC]['KeyDir'] != '':
                if int(self.__NodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                    if ffNodeMAC in self.__NodeMoveDict:
                        print('!! Multiple Move: %s -> %s' % (ffNodeMAC,TargetSeg))

                    if TargetSeg == 0:
                        print('!! No move to Legacy: %s/peers/%s\n' % (self.__NodeDict[ffNodeMAC]['KeyDir'],self.__NodeDict[ffNodeMAC]['KeyFile']) )
                    else:
                        self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                        print('>> git mv %s/peers/%s vpn%02d/peers/  = \'%s\'\n' % ( self.__NodeDict[ffNodeMAC]['KeyDir'],self.__NodeDict[ffNodeMAC]['KeyFile'],
                                                                                 TargetSeg,self.__NodeDict[ffNodeMAC]['Name'] ))
        return



    #-----------------------------------------------------------------------
    # private function "__GetUplinkList"
    #
    #   returns UplinkList from NodeList verified by batman traceroute
    #
    #-----------------------------------------------------------------------
    def __GetUplinkList(self,NodeList,SegmentSearchList):

        print('... Analysing Batman Traceroute: %s -> %s ...' % (NodeList,SegmentSearchList))
        UplinkList = []

        for ffSeg in SegmentSearchList:
            for ffNodeMAC in NodeList:
                BatctlCmd = ('/usr/sbin/batctl -m bat%02d tr %s' % (ffSeg,ffNodeMAC)).split()

                try:
                    BatctlTr = subprocess.run(BatctlCmd, stdout=subprocess.PIPE, timeout=BatmanTimeout)
                    BatctlResult = BatctlTr.stdout.decode('utf-8')
                except:
                    print('++ ERROR accessing batman: % s' % (BatctlCmd))
                else:
                    MeshMAC = None

                    for BatctlLine in BatctlResult.split('\n'):
                        BatctlInfo = BatctlLine.replace('(',' ').replace(')',' ').split()
#                        print(MeshMAC,BatctlInfo)

                        if len(BatctlInfo) > 3:
                            if BatctlInfo[0] == 'traceroute':
                                MeshMAC = BatctlInfo[3]
                            elif MeshMAC is not None:
                                if MacAdrTemplate.match(BatctlInfo[1]) and not GwMacTemplate.match(BatctlInfo[1]):
                                    if BatctlInfo[1] == MeshMAC:
                                        UplinkList.append(ffNodeMAC)
                                        self.__NodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                                        self.__NodeDict[ffNodeMAC]['Segment'] = ffSeg
                                    break

        return UplinkList



    #==============================================================================
    # public function "CheckMeshClouds"
    #
    #   Analysing Mesh Clouds for Segment Shortcuts and set common Segment
    #
    #==============================================================================
    def CheckMeshClouds(self):

        print('Checking Mesh-Clouds ...')

        for CloudID in self.__MeshCloudDict:
            DesiredSegDict = {}    # Weight of Nodes per desired Segments
            CurrentSegList = []    # List of current Segments of the Nodes
            UpLinkSegDict  = {}    # Weight of UpLink-Nodes per Segment
            UpTimeSegDict  = {}    # max. UpTime of Uplink-Nodes per Segment

            #---------- Analysing nodes and related desired segments ----------
            for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
                NodeSeg = self.__NodeDict[ffNodeMAC]['Segment']

                if NodeSeg is not None:
                    if NodeSeg not in CurrentSegList:
                        CurrentSegList.append(NodeSeg)

                if self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    if self.__NodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    else:
                        NodeWeigt = NODEWEIGHT_UPLINK

                    if NodeSeg not in UpLinkSegDict:
                        UpLinkSegDict[NodeSeg] = NodeWeigt
                    else:
                        UpLinkSegDict[NodeSeg] += NodeWeigt

                    if NodeSeg not in UpTimeSegDict:
                        UpTimeSegDict[NodeSeg] = 0.0

                    if self.__NodeDict[ffNodeMAC]['Uptime'] > UpTimeSegDict[NodeSeg]:
                        UpTimeSegDict[NodeSeg] = self.__NodeDict[ffNodeMAC]['Uptime']

                else:
                    if self.__NodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    elif self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_MESH:
                        NodeWeigt = NODEWEIGHT_MESH_ONLY
                    else:
                        NodeWeigt = NODEWEIGHT_OFFLINE

                if self.__NodeDict[ffNodeMAC]['DestSeg'] is not None:
                    if self.__NodeDict[ffNodeMAC]['DestSeg'] not in DesiredSegDict:
                        DesiredSegDict[self.__NodeDict[ffNodeMAC]['DestSeg']] = NodeWeigt
                    else:
                        DesiredSegDict[self.__NodeDict[ffNodeMAC]['DestSeg']] += NodeWeigt

            if len(UpLinkSegDict) == 0:
                print('++ Cloud seems to be w/o VPN Uplink(s):',self.__MeshCloudDict[CloudID]['CloudMembers'])
                SearchList = CurrentSegList

                for Segment in DesiredSegDict:
                    if Segment not in SearchList:
                        SearchList.append(Segment)

                for ffNodeMAC in self.__GetUplinkList(self.__MeshCloudDict[CloudID]['CloudMembers'],SearchList):
                    NodeSeg = self.__NodeDict[ffNodeMAC]['Segment']
                    print('>> Uplink found by Batman: Seg.%02d - %s = \'%s\'' % (NodeSeg,ffNodeMAC,self.__NodeDict[ffNodeMAC]['Name']))

                    if self.__NodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    else:
                        NodeWeigt = NODEWEIGHT_UPLINK

                    if NodeSeg not in UpLinkSegDict:
                        UpLinkSegDict[NodeSeg] = NodeWeigt
                    else:
                        UpLinkSegDict[NodeSeg] += NodeWeigt

                    if NodeSeg not in UpTimeSegDict:
                        UpTimeSegDict[NodeSeg] = 0.0

                    if self.__NodeDict[ffNodeMAC]['Uptime'] > UpTimeSegDict[NodeSeg]:
                        UpTimeSegDict[NodeSeg] = self.__NodeDict[ffNodeMAC]['Uptime']

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
                self.__alert('!! Shortcut detected in Cloud %s: UplinkSegs = %d / CurrentSegs = %d' % (CloudID,len(UpLinkSegDict),len(CurrentSegList)))

                if CloudSegment is None:
                    self.__alert('!! Shortcut cannot be corrected, missing CloudSegment !!')
                    self.AnalyseOnly = True
                else:
                    self.__alert('** Shortcut in Cloud %s will be corrected, Number of Nodes = %d, Segment = %02d  ...' %
                                    (CloudID,len(self.__MeshCloudDict[CloudID]['CloudMembers']),CloudSegment))
                    print(self.__MeshCloudDict[CloudID]['CloudMembers'])
                    print()

            if CloudSegment is not None:
                self.__MarkNodesInCloudForMove(CloudID,CloudSegment)

        print('... done.\n')
        return



    #==============================================================================
    # public function "CheckSingleNodes"
    #
    #   Check if Node is in correct Segment
    #
    #==============================================================================
    def CheckSingleNodes(self):

        print('Checking Single Nodes ...')

        for ffNodeMAC in self.__NodeDict.keys():
            if ((self.__NodeDict[ffNodeMAC]['InCloud'] is None and self.__NodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN) and
                (self.__NodeDict[ffNodeMAC]['KeyDir'][:3] == 'vpn')):

                if self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_MESH:
                    print('++ Node seems to be w/o VPN Uplink: %s / %s = \'%s\'' % (self.__NodeDict[ffNodeMAC]['KeyDir'],ffNodeMAC,self.__NodeDict[ffNodeMAC]['Name']))

                    for UplinkNodeMAC in self.__GetUplinkList([ffNodeMAC],[int(self.__NodeDict[ffNodeMAC]['KeyDir'][3:])]):
                        self.__NodeDict[UplinkNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                        print('>> Uplink found by Batman:',UplinkNodeMAC)

                TargetSeg = self.__NodeDict[ffNodeMAC]['DestSeg']

                if TargetSeg is not None:
                    if int(self.__NodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                        if TargetSeg <= 8 or self.__NodeDict[ffNodeMAC]['GluonType'] >= NODETYPE_DNS_SEGASSIGN:
                            if ffNodeMAC in self.__NodeMoveDict:
                                print('!! Multiple Move:',ffNodeMAC,'->',TargetSeg)

                            self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                            print('>> git mv %s/peers/%s vpn%02d/peers/  = \'%s\'' % (self.__NodeDict[ffNodeMAC]['KeyDir'],self.__NodeDict[ffNodeMAC]['KeyFile'],
                                                                                      TargetSeg,self.__NodeDict[ffNodeMAC]['Name'] ))
                        else:
                            print('!! Gluon too old for desired Segment: %s = \'%s\' -> Seg. %02d' % (ffNodeMAC,self.__NodeDict[ffNodeMAC]['Name'],TargetSeg))

        print('... done.\n')
        return



    #==============================================================================
    # public function "GetMoveDict"
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



    #-----------------------------------------------------------------------
    # private function "__WriteMeshClouds"
    #
    #
    #-----------------------------------------------------------------------
    def __WriteMeshClouds(self,MeshCloudFile):

        print('\nWriting out Nodes in Mesh Clouds ...')
        MeshCloudFile.write('FF-Mesh-Clouds on %s\n' % datetime.datetime.now())
        TotalMeshingNodes = 0

        for CloudID in sorted(self.__MeshCloudDict):

            TotalNodes    = 0
            TotalClients  = 0
            TotalUplinks  = 0

            CurrentSeg    = self.__MeshCloudDict[CloudID]['CloudSegment']
            CurrentVPN    = None
            CurrentRegion = None
            CurrentZIP    = None
            CurrentError  = ''

            MeshCloudFile.write('\n------------------------------------------------------------------------------------------------------------------\n')
            TotalMeshingNodes += len(self.__MeshCloudDict[CloudID]['CloudMembers'])

            for ffnb in sorted(self.__MeshCloudDict[CloudID]['CloudMembers']):
                CurrentError = ' '

                if self.__NodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeDict[ffnb]['Segment']

                    if CurrentSeg is None:
                        print('++ ERROR CloudSegment is None -> Setting Seg. %02d !!' % (Segment))
                        CurrentSeg = Segment
                    elif Segment != CurrentSeg:
#                        print('++ ERROR Segment:',ffnb,'=',CurrentSeg,'<>',Segment)
                        CurrentError = '!'

                    if CurrentRegion is None or CurrentRegion == '??':
                        CurrentRegion = self.__NodeDict[ffnb]['Region']
                    elif self.__NodeDict[ffnb]['Region'] != '??' and self.__NodeDict[ffnb]['Region'] != CurrentRegion:
                        print('++ ERROR Region:',ffnb,'= \''+self.__NodeDict[ffnb]['Name']+'\' ->',self.__NodeDict[ffnb]['Region'],'<>',CurrentRegion)
                        CurrentError = '!'

                    if CurrentZIP is None:
                        CurrentZIP = self.__NodeDict[ffnb]['ZIP']

                if CurrentError == ' ' and self.__NodeDict[ffnb]['SegMode'] != 'auto':
                    CurrentError = '+'

                if CurrentError == ' ' and self.__NodeDict[ffnb]['KeyDir'] != '':
                    if ((self.__NodeDict[ffnb]['Segment'] is not None and int(self.__NodeDict[ffnb]['KeyDir'][3:]) != self.__NodeDict[ffnb]['Segment']) or
                        (self.__NodeDict[ffnb]['DestSeg'] is not None and self.__NodeDict[ffnb]['DestSeg'] != self.__NodeDict[ffnb]['Segment'])):
                        print('++ ERROR Region:',self.__NodeDict[ffnb]['Status'],ffnb,'= \''+self.__NodeDict[ffnb]['Name']+'\' ->',
                              self.__NodeDict[ffnb]['KeyDir'],self.__NodeDict[ffnb]['Segment'],'->',
                              self.__NodeDict[ffnb]['DestSeg'],self.__NodeDict[ffnb]['SegMode'])
                        CurrentError = '>'

                if CurrentVPN is None and self.__NodeDict[ffnb]['KeyDir'] != '':
                    CurrentVPN = self.__NodeDict[ffnb]['KeyDir']
                elif CurrentVPN is not None and self.__NodeDict[ffnb]['KeyDir'] != '' and self.__NodeDict[ffnb]['KeyDir'] != CurrentVPN:
                    print('++ ERROR KeyDir:',self.__NodeDict[ffnb]['Status'],ffnb,'=',CurrentVPN,'<>',self.__NodeDict[ffnb]['KeyDir'])
                    CurrentError = '*'

                if CurrentError == ' ':
                    CurrentError = GLUON_MARKER[self.__NodeDict[ffnb]['GluonType']]

                MeshCloudFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = \'%s\' (%s = %s) UpT = %d\n' % (CurrentError, self.__NodeDict[ffnb]['Status'], Segment,
                                                                                                self.__NodeDict[ffnb]['Clients'], ffnb, self.__NodeDict[ffnb]['KeyDir'],
                                                                                                self.__NodeDict[ffnb]['KeyFile'], self.__NodeDict[ffnb]['Name'],
                                                                                                self.__NodeDict[ffnb]['DestSeg'], self.__NodeDict[ffnb]['Region'],
                                                                                                self.__NodeDict[ffnb]['Uptime']))

                if self.__NodeDict[ffnb]['Status'] in [ NODESTATE_ONLINE_MESH, NODESTATE_ONLINE_VPN ]:
                    TotalNodes   += 1
                    TotalClients += self.__NodeDict[ffnb]['Clients']

                if self.__NodeDict[ffnb]['Status'] == NODESTATE_ONLINE_VPN:
                    TotalUplinks += 1

            MeshCloudFile.write('\n          Total Online-Nodes / Clients / Uplinks = %3d / %3d / %3d   (Seg. %02d)\n' % (TotalNodes,TotalClients,TotalUplinks,CurrentSeg))

            for ffnb in self.__MeshCloudDict[CloudID]['CloudMembers']:
                self.__NodeDict[ffnb]['Segment'] = CurrentSeg
                self.__NodeDict[ffnb]['Region']  = CurrentRegion
                self.__NodeDict[ffnb]['ZIP']     = CurrentZIP

        print('\nSum: %d Clouds with %d Nodes\n' % (len(self.__MeshCloudDict),TotalMeshingNodes))
        MeshCloudFile.write('\nSum: %d Clouds with %d Nodes\n' % (len(self.__MeshCloudDict),TotalMeshingNodes))
        return



    #-----------------------------------------------------------------------
    # private function "__WriteSingleNodes"
    #
    #
    #-----------------------------------------------------------------------
    def __WriteSingleNodes(self,MeshCloudFile):

        print('\nWriting out Single Nodes ...')
        MeshCloudFile.write('\n\n########################################################################\n\n')
        MeshCloudFile.write('Single Nodes:\n\n')

        for ffnb in sorted(self.__NodeDict.keys()):
            if (self.__NodeDict[ffnb]['InCloud'] is None
            and self.__NodeDict[ffnb]['Status'] in [ NODESTATE_ONLINE_MESH, NODESTATE_ONLINE_VPN ]
            and self.__NodeDict[ffnb]['KeyDir'] != ''):

                CurrentError = ' '

                if self.__NodeDict[ffnb]['SegMode'] != 'auto':
                    CurrentError = '+'

                elif self.__NodeDict[ffnb]['DestSeg'] is not None and self.__NodeDict[ffnb]['DestSeg'] != int(self.__NodeDict[ffnb]['KeyDir'][3:]):
                    print('++ ERROR Region:',self.__NodeDict[ffnb]['Status'],ffnb,self.__NodeDict[ffnb]['KeyDir'],
                          self.__NodeDict[ffnb]['Segment'],'->',self.__NodeDict[ffnb]['DestSeg'],self.__NodeDict[ffnb]['SegMode'])

                    CurrentError = '>'

                if self.__NodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeDict[ffnb]['Segment']

                if CurrentError == ' ':
                    CurrentError = GLUON_MARKER[self.__NodeDict[ffnb]['GluonType']]

                MeshCloudFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = \'%s\' (%s = %s) UpT = %d\n' % (CurrentError, self.__NodeDict[ffnb]['Status'],
                                                                                                Segment,self.__NodeDict[ffnb]['Clients'], ffnb,
                                                                                                self.__NodeDict[ffnb]['KeyDir'], self.__NodeDict[ffnb]['KeyFile'],
                                                                                                self.__NodeDict[ffnb]['Name'], self.__NodeDict[ffnb]['DestSeg'],
                                                                                                self.__NodeDict[ffnb]['Region'], self.__NodeDict[ffnb]['Uptime']))
        return



    #-----------------------------------------------------------------------
    # private function "__CalculateStatistics"
    #
    #
    #-----------------------------------------------------------------------
    def __CalculateStatistics(self,SegmentDict,RegionDict):

        for ffNodeMAC in self.__NodeDict.keys():
            if self.__NodeDict[ffNodeMAC]['Status'] in [ NODESTATE_ONLINE_MESH, NODESTATE_ONLINE_VPN ]:
                ffSegment = self.__NodeDict[ffNodeMAC]['Segment']
                ffRegion  = self.__NodeDict[ffNodeMAC]['Region']

                if ffSegment not in SegmentDict:
                    SegmentDict[ffSegment] = { 'Nodes':0, 'Clients':0, 'Uplinks':0, 'BlindLoad':0 }

                SegmentDict[ffSegment]['Nodes'] += 1
                SegmentDict[ffSegment]['Clients'] += self.__NodeDict[ffNodeMAC]['Clients']

                if self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    SegmentDict[ffSegment]['Uplinks'] += 1

                ffRegion  = self.__NodeDict[ffNodeMAC]['Region']

                if ffRegion is None or ffRegion == '??':
                    SegmentDict[ffSegment]['BlindLoad'] += 1 + self.__NodeDict[ffNodeMAC]['Clients']
                    ffRegion = '-- undefined --'
                    ffSegment = 0

                if ffRegion not in RegionDict:
                    RegionDict[ffRegion] = { 'Nodes':0, 'Clients':0, 'OldGluon':0, 'Segment':ffSegment }

                RegionDict[ffRegion]['Nodes']    += 1
                RegionDict[ffRegion]['Clients']  += self.__NodeDict[ffNodeMAC]['Clients']

                if self.__NodeDict[ffNodeMAC]['GluonType'] < NODETYPE_MTU_1340:
                    RegionDict[ffRegion]['OldGluon'] += 1

        return



    #-----------------------------------------------------------------------
    # private function "__WriteStatistics"
    #
    #
    #-----------------------------------------------------------------------
    def __WriteStatistics(self,MeshCloudFile):

        SegmentDict = {}
        RegionDict  = {}

        self.__CalculateStatistics(SegmentDict,RegionDict)

        print('\nWrite out Statistics ...')
        MeshCloudFile.write('\n\n########################################################################\n\n')
        MeshCloudFile.write('Online-Nodes      / Clients / Sum:\n\n')

        TotalNodes   = 0
        TotalClients = 0
        TotalUplinks = 0

        for ffSeg in sorted(SegmentDict):
            MeshCloudFile.write('Segment %02d: %5d / %5d / %5d / (%d)\n' % (ffSeg, SegmentDict[ffSeg]['Nodes'], SegmentDict[ffSeg]['Clients'], SegmentDict[ffSeg]['Nodes']+SegmentDict[ffSeg]['Clients'],SegmentDict[ffSeg]['BlindLoad']))
            TotalNodes   += SegmentDict[ffSeg]['Nodes']
            TotalClients += SegmentDict[ffSeg]['Clients']
#            TotalUplinks += SegmentDict[ffSeg]['Uplinks']


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
        return



    #==============================================================================
    # public function "WriteMeshCloudList"
    #
    #   Write out Mesh Cloud List
    #==============================================================================
    def WriteMeshCloudList(self,FileName):

        print('Writing out Mesh Cloud List ...')
        MeshCloudFile = open(FileName, mode='w')

        self.__WriteMeshClouds(MeshCloudFile)
        self.__WriteSingleNodes(MeshCloudFile)
        self.__WriteStatistics(MeshCloudFile)

        MeshCloudFile.close()
        print()
        return
