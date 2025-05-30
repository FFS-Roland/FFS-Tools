#!/usr/bin/python3

#################################################################################################
#                                                                                               #
#   class_ffMeshNet.py                                                                          #
#                                                                                               #
#   Combining and analysing Data from Nodes and Gateways to find Mesh-Clouds.                   #
#                                                                                               #
#                                                                                               #
#   Needed Python Classes:                                                                      #
#                                                                                               #
#       class_ffNodeInfo     -> Node Names and Information                                      #
#       class_ffGatewayInfo  -> Keys and Segment Information                                    #
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
            if self.__NodeDict[ffNodeMAC]['FastdKey'] is not None:
                if int(self.__NodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                    FastdKey = self.__NodeDict[ffNodeMAC]['FastdKey']

                    if FastdKey in self.__NodeMoveDict:
                        print('!! Multiple Move: %s / %s -> %s' % (FastdKey,ffNodeMAC,TargetSeg))

                    if TargetSeg == 0:
                        print('!! No move to Legacy: %s/peers/%s\n' % (self.__NodeDict[ffNodeMAC]['KeyDir'],self.__NodeDict[ffNodeMAC]['KeyFile']) )
                    else:
                        self.__NodeMoveDict[FastdKey] = TargetSeg
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
                BatctlCmd = ('/usr/sbin/batctl meshif bat%02d tr %s' % (ffSeg,ffNodeMAC)).split()

                try:
                    BatctlTr = subprocess.run(BatctlCmd, stdout=subprocess.PIPE, timeout=BatmanTimeout)
                    BatctlResult = BatctlTr.stdout.decode('utf-8')
                except:
                    print('++ ERROR accessing batman: % s' % (BatctlCmd))
                else:
                    MeshMAC = None
                    GwMAC = None

                    for BatctlLine in BatctlResult.split('\n'):
                        BatctlInfo = BatctlLine.replace('(',' ').replace(')',' ').split()
#                        print(MeshMAC,BatctlInfo)

                        if len(BatctlInfo) > 3:
                            if BatctlInfo[0] == 'traceroute':
                                MeshMAC = BatctlInfo[3]
                            elif MeshMAC is not None:
                                if MacAdrTemplate.match(BatctlInfo[1]):
                                    if GwMacTemplate.match(BatctlInfo[1]):
                                        GwMAC = BatctlInfo[1]
                                    elif GwMAC is not None:
                                        if BatctlInfo[1] == MeshMAC:
                                            UplinkList.append(ffNodeMAC)
                                            self.__NodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                                            self.__NodeDict[ffNodeMAC]['FastdGW'] = 'gw%sn%s' % (GwMAC[12:14],GwMAC[15:17])
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
            DesiredSegDict = {}    # Weight and UpTime of Nodes per Home-Segment
            UpLinkSegDict  = {}    # Weight and UpTime of UpLink-Nodes per Segment
            CurrentSegList = []    # List of current Segments of the Nodes

            #---------- Analysing nodes and related desired segments ----------
            for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
                NodeSeg = self.__NodeDict[ffNodeMAC]['Segment']
                HomeSeg = self.__NodeDict[ffNodeMAC]['HomeSeg']


                if self.__NodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                    NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                elif self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    NodeWeigt = NODEWEIGHT_UPLINK
                elif self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_MESH:
                    NodeWeigt = NODEWEIGHT_MESH_ONLY
                else:
                    NodeWeigt = NODEWEIGHT_OFFLINE

                if HomeSeg is not None:
                    if HomeSeg not in DesiredSegDict:
                        DesiredSegDict[HomeSeg] = { 'Weight': NodeWeigt, 'UpTime': self.__NodeDict[ffNodeMAC]['UpTime'] }
                    else:
                        DesiredSegDict[HomeSeg]['Weight'] += NodeWeigt

                        if self.__NodeDict[ffNodeMAC]['UpTime'] > DesiredSegDict[HomeSeg]['UpTime']:
                            DesiredSegDict[HomeSeg]['UpTime'] = self.__NodeDict[ffNodeMAC]['UpTime']

                if NodeSeg is not None:
                    if NodeSeg not in CurrentSegList:
                        CurrentSegList.append(NodeSeg)

                    if self.__NodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                        if NodeSeg not in UpLinkSegDict:
                            UpLinkSegDict[NodeSeg] = { 'Weight': NodeWeigt, 'UpTime': self.__NodeDict[ffNodeMAC]['UpTime'] }
                        else:
                            UpLinkSegDict[NodeSeg]['Weight'] += NodeWeigt

                            if self.__NodeDict[ffNodeMAC]['UpTime'] > UpLinkSegDict[NodeSeg]['UpTime']:
                                UpLinkSegDict[NodeSeg]['UpTime'] = self.__NodeDict[ffNodeMAC]['UpTime']

            if len(UpLinkSegDict) == 0:
                print('++ Cloud seems to be w/o VPN Uplink(s):',self.__MeshCloudDict[CloudID]['CloudMembers'])
                SearchList = CurrentSegList

                for Segment in DesiredSegDict:
                    if Segment not in SearchList:
                        SearchList.append(Segment)

                for ffNodeMAC in self.__GetUplinkList(self.__MeshCloudDict[CloudID]['CloudMembers'],SearchList):
                    NodeSeg = self.__NodeDict[ffNodeMAC]['Segment']
                    print('>> Uplink found by Batman: Seg.%02d %s - %s = \'%s\'' % (NodeSeg,self.__NodeDict[ffNodeMAC]['FastdGW'],ffNodeMAC,self.__NodeDict[ffNodeMAC]['Name']))

                    if self.__NodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':
                        NodeWeigt = NODEWEIGHT_SEGMENT_FIX
                    else:
                        NodeWeigt = NODEWEIGHT_UPLINK

                    if NodeSeg not in UpLinkSegDict:
                        UpLinkSegDict[NodeSeg] = { 'Weight': NodeWeigt, 'UpTime': self.__NodeDict[ffNodeMAC]['UpTime'] }
                    else:
                        UpLinkSegDict[NodeSeg]['Weight'] += NodeWeigt

                        if self.__NodeDict[ffNodeMAC]['UpTime'] > UpLinkSegDict[NodeSeg]['UpTime']:
                            UpLinkSegDict[NodeSeg]['UpTime'] = self.__NodeDict[ffNodeMAC]['UpTime']

            #---------- Calculating desired Segment for the Cloud ----------
            CloudSegment = None
            SegWeight = 0
            SegUpTime = 0

            for Segment in DesiredSegDict:
                if (DesiredSegDict[Segment]['Weight'] > SegWeight
                or (DesiredSegDict[Segment]['Weight'] == SegWeight and DesiredSegDict[Segment]['UpTime'] > SegUpTime)):
                    CloudSegment = Segment
                    SegWeight = DesiredSegDict[Segment]['Weight']
                    SegUpTime = DesiredSegDict[Segment]['UpTime']

            if CloudSegment is None:
                for Segment in UpLinkSegDict:
                    if (UpLinkSegDict[Segment]['Weight'] > SegWeight
                    or (UpLinkSegDict[Segment]['Weight'] == SegWeight and UpLinkSegDict[Segment]['UpTime'] > SegUpTime)):
                        CloudSegment = Segment
                        SegWeight = UpLinkSegDict[Segment]['Weight']
                        SegUpTime = UpLinkSegDict[Segment]['UpTime']

            self.__MeshCloudDict[CloudID]['CloudSegment'] = CloudSegment

            #---------- Actions depending of situation in cloud ----------
            if len(CurrentSegList) > 1:
                self.__alert('!! Shortcut detected in Cloud %s: CurrentSegs = %d / UplinkSegs = %d' % (CloudID,len(CurrentSegList),len(UpLinkSegDict)))
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
                    NodeSeg = int(self.__NodeDict[ffNodeMAC]['KeyDir'][3:])

                    for UplinkNodeMAC in self.__GetUplinkList([ffNodeMAC],[ NodeSeg ]):
                        print('>> Uplink found by Batman: Seg.%02d %s - %s = \'%s\'' %
                                (NodeSeg,self.__NodeDict[ffNodeMAC]['FastdGW'],UplinkNodeMAC,self.__NodeDict[UplinkNodeMAC]['Name']))

                TargetSeg = self.__NodeDict[ffNodeMAC]['HomeSeg']

                if TargetSeg is not None:
                    if int(self.__NodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                        if TargetSeg <= 8 or self.__NodeDict[ffNodeMAC]['GluonType'] >= NODETYPE_DNS_SEGASSIGN:
                            FastdKey = self.__NodeDict[ffNodeMAC]['FastdKey']

                            if FastdKey in self.__NodeMoveDict:
                                print('!! Multiple Move: %s / %s -> %s' % (FastdKey,ffNodeMAC,TargetSeg))

                            self.__NodeMoveDict[FastdKey] = TargetSeg
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
                        (self.__NodeDict[ffnb]['HomeSeg'] is not None and self.__NodeDict[ffnb]['HomeSeg'] != self.__NodeDict[ffnb]['Segment'])):
                        print('++ ERROR Region:',self.__NodeDict[ffnb]['Status'],ffnb,'= \''+self.__NodeDict[ffnb]['Name']+'\' ->',
                              self.__NodeDict[ffnb]['KeyDir'],self.__NodeDict[ffnb]['Segment'],'->',
                              self.__NodeDict[ffnb]['HomeSeg'],self.__NodeDict[ffnb]['SegMode'])
                        CurrentError = '>'

                if CurrentVPN is None and self.__NodeDict[ffnb]['KeyDir'] != '':
                    CurrentVPN = self.__NodeDict[ffnb]['KeyDir']
                elif CurrentVPN is not None and self.__NodeDict[ffnb]['KeyDir'] != '' and self.__NodeDict[ffnb]['KeyDir'] != CurrentVPN:
                    print('++ ERROR KeyDir:',self.__NodeDict[ffnb]['Status'],ffnb,'=',CurrentVPN,'<>',self.__NodeDict[ffnb]['KeyDir'])
                    CurrentError = '*'

                if CurrentError == ' ':
                    CurrentError = GLUON_MARKER[self.__NodeDict[ffnb]['GluonType']]

                if self.__NodeDict[ffnb]['FastdGW'] is None:
                    self.__NodeDict[ffnb]['FastdGW'] = ''

                MeshCloudFile.write('%s%s Seg.%02d [%3d] %s = %7s - %16s = \'%s\' (%s = %s) UpT = %d\n' % (CurrentError, self.__NodeDict[ffnb]['Status'], Segment,
                                                                                                self.__NodeDict[ffnb]['Clients'], ffnb, self.__NodeDict[ffnb]['FastdGW'],
                                                                                                self.__NodeDict[ffnb]['KeyFile'], self.__NodeDict[ffnb]['Name'],
                                                                                                self.__NodeDict[ffnb]['HomeSeg'], self.__NodeDict[ffnb]['Region'],
                                                                                                self.__NodeDict[ffnb]['UpTime']))

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

                elif self.__NodeDict[ffnb]['HomeSeg'] is not None and self.__NodeDict[ffnb]['HomeSeg'] != int(self.__NodeDict[ffnb]['KeyDir'][3:]):
                    print('++ ERROR Region:',self.__NodeDict[ffnb]['Status'],ffnb,self.__NodeDict[ffnb]['KeyDir'],
                          self.__NodeDict[ffnb]['Segment'],'->',self.__NodeDict[ffnb]['HomeSeg'],self.__NodeDict[ffnb]['SegMode'])

                    CurrentError = '>'

                if self.__NodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeDict[ffnb]['Segment']

                if CurrentError == ' ':
                    CurrentError = GLUON_MARKER[self.__NodeDict[ffnb]['GluonType']]

                if self.__NodeDict[ffnb]['FastdGW'] is None:
                    self.__NodeDict[ffnb]['FastdGW'] = ''

                MeshCloudFile.write('%s%s Seg.%02d [%3d] %s = %7s - %16s = \'%s\' (%s = %s) UpT = %d\n' % (CurrentError, self.__NodeDict[ffnb]['Status'],
                                                                                                Segment,self.__NodeDict[ffnb]['Clients'], ffnb,
                                                                                                self.__NodeDict[ffnb]['FastdGW'], self.__NodeDict[ffnb]['KeyFile'],
                                                                                                self.__NodeDict[ffnb]['Name'], self.__NodeDict[ffnb]['HomeSeg'],
                                                                                                self.__NodeDict[ffnb]['Region'], self.__NodeDict[ffnb]['UpTime']))
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

                if self.__NodeDict[ffNodeMAC]['GluonType'] < NODETYPE_MCAST_ff05:
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
