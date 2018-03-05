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

        self.__DefaultTarget  = 3       # Target Segment to use if no better Data available

        # Initializations
        self.__CheckConsistency()

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

        if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Status'] != '?' and ffNeighbourMAC not in self.__MeshCloudDict[CloudID]['CloudMembers']:

            if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] is None:
                self.__MeshCloudDict[CloudID]['NumClients'] += self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Clients']
                self.__MeshCloudDict[CloudID]['CloudMembers'].append(ffNeighbourMAC)
                self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] = CloudID

                if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['GluonType'] < self.__MeshCloudDict[CloudID]['GluonType'] and self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Status'] == 'V':
                    self.__MeshCloudDict[CloudID]['GluonType'] = self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['GluonType']
#                    if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['GluonType'] < 3:
#                        print('>>> GluonType:',ffNeighbourMAC,'=',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name'])

                for MeshMAC in self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Neighbours']:
                    if MeshMAC in self.__NodeInfos.MAC2NodeIDDict:
#                        print('+',Cloud,MAC2NodeIDDict[MeshMAC])
                        self.__AddNeighbour2Cloud(CloudID,self.__NodeInfos.MAC2NodeIDDict[MeshMAC])
                    else:
                        print('!! Unknown Neighbour:',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Segment'],'-',ffNeighbourMAC,'=',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name'].encode('UTF-8'),'->',MeshMAC)
            elif self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] == CloudID:
                print('!! Cloud inconsistent:',CloudID,'-',ffNeighbourMAC,'=',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name'].encode('UTF-8'),'->',self.__MeshCloudDict[CloudID]['CloudMembers'])
            else:
                # Node is already part of another Mesh Cloud -> merge Clouds
                oldCloudID = self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud']
    #            print('++ Merging Clouds:',ffNeighbourMAC,'=',ffNodeDict[ffNeighbourMAC]['Name'].encode('UTF-8'),oldCloudID,'->',CloudID)

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
            if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != '?' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] is None) and
                (len(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Neighbours']) > 0)):

                self.__MeshCloudDict[ffNodeMAC] = {
                    'NumClients': 0,
                    'GluonType': 99,
                    'CloudMembers': []
                }

                self.__AddNeighbour2Cloud(ffNodeMAC,ffNodeMAC)

                if len(self.__MeshCloudDict[ffNodeMAC]['CloudMembers']) < 2:
                    print('++ Single-Node Cloud:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'],'-',ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] = None
                    del self.__MeshCloudDict[ffNodeMAC]
                else:
                    TotalNodes   += len(self.__MeshCloudDict[ffNodeMAC]['CloudMembers'])
                    TotalClients += self.__MeshCloudDict[ffNodeMAC]['NumClients']

        print('... Number of Clouds / Nodes / Clients:',len(self.__MeshCloudDict),'/',TotalNodes,'/',TotalClients)
        print()
        return



    #-----------------------------------------------------------------------
    # private function "__MoveNodesInCloud"
    #
    #   Move Nodes to other Segement
    #
    #-----------------------------------------------------------------------
    def __MoveNodesInCloud(self,CloudID,TargetSeg):

        for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
            if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                    if ffNodeMAC in self.__NodeMoveDict:
                        print('!! Multiple Move:',ffNodeMAC,'->',TargetSeg)

                    if TargetSeg == 0:
                        print('!! No move to Legacy: %s/peers/%s\n' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']) )
                    else:
                        self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                        print('>> git mv %s/peers/%s vpn%02d/peers/  = %s\n' % ( self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                                 TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8') ))

        return



    #-----------------------------------------------------------------------
    # private function "__HandleShortcut"
    #
    #   Handle Segment Shortcut
    #
    #-----------------------------------------------------------------------
    def __HandleShortcut(self,CloudID,DesiredSegDict,FixedSegList):

        SegWeight = 0
        TargetSeg = None  # Target where all nodes of this cloud must be moved to

        if len(FixedSegList) > 0:
            if len(FixedSegList) > 1:
                self.__alert('!! ALARM - Multiple Segments with fixed Nodes!')
                print('->',FixedSegList,self.__MeshCloudDict[CloudID])
                self.AnalyseOnly = True

            else:   #----- exactly one Segment with fixed Nodes
                for Segment in FixedSegList:
                    TargetSeg = Segment

        else:   #----- No fixed Nodes -----
            for Segment in DesiredSegDict:
                if Segment <= 8 or self.__MeshCloudDict[CloudID]['GluonType'] > 2:
                    if DesiredSegDict[Segment] > SegWeight:
                        SegWeight = DesiredSegDict[Segment]
                        TargetSeg = Segment

            if TargetSeg is None:
                TargetSeg = self.__DefaultTarget

        if TargetSeg is not None:
            self.__MoveNodesInCloud(CloudID,TargetSeg)
            self.__alert('!! Shortcut detected !!!')
            print(self.__MeshCloudDict[CloudID]['CloudMembers'])
            print()

        return



    #-----------------------------------------------------------------------
    # private function "__HandleSegmentAssignment"
    #
    #   Segment Assignment of Nodes in Mesh Cloud w/o shortcuts or fixes
    #
    #-----------------------------------------------------------------------
    def __HandleSegmentAssignment(self,CloudID,DesiredSegDict,ActiveSegList):

        SegWeight = 0
        TargetSeg = None

        if len(DesiredSegDict) == 0:
            if 0 in ActiveSegList:  # Cloud in Legacy Segment
                TargetSeg = self.__DefaultTarget
        else:
            for Segment in DesiredSegDict.keys():
                if Segment <= 8 or self.__MeshCloudDict[CloudID]['GluonType'] > 2:
                    if DesiredSegDict[Segment] > SegWeight:
                        SegWeight = DesiredSegDict[Segment]
                        TargetSeg = Segment

                else:
                    print('>>> No Segament Assignment:',CloudID,'=',Segment,'->',self.__MeshCloudDict[CloudID]['GluonType'])

        if TargetSeg is not None:
            self.__MoveNodesInCloud(CloudID,TargetSeg)

        return



    #-----------------------------------------------------------------------
    # private function "__CheckMeshClouds"
    #
    #   Analysing Mesh Clouds for Segment Shortcuts
    #
    #-----------------------------------------------------------------------
    def __CheckMeshClouds(self):

        print('Checking Mesh-Clouds ...')

        for CloudID in self.__MeshCloudDict:
            DesiredSegDict = {}    # desired segments with number of nodes
            ActiveSegList  = []    # really used segments
            UplinkSegList  = []    # List of segments from nodes with uplink
            FixedSegList   = []    # List of segments from nodes with fixed segment assignment
            isOnline       = False

            #---------- Analysing used segments with their nodes and clients ----------
            for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
                VpnSeg = None

                if self.__NodeInfos.IsOnline(ffNodeMAC):
                    isOnline = True

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] not in ActiveSegList:
                        ActiveSegList.append(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == 'V' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][:3] == 'vpn':
                        VpnSeg = int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])

                        if VpnSeg not in UplinkSegList:
                            UplinkSegList.append(VpnSeg)

                DestSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']

                if DestSeg is None:
                    if VpnSeg is not None:
                        DestSeg = VpnSeg
                        Weight = 2
                    else:
                        Weight = 1
                elif VpnSeg is not None and VpnSeg == DestSeg:
                    Weight = 4
                else:
                    Weight = 2

                if DestSeg is not None and DestSeg != 0:
                    if DestSeg not in DesiredSegDict:
                        DesiredSegDict[DestSeg] =  Weight
                    else:
                        DesiredSegDict[DestSeg] += Weight

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] != 'auto' or VpnSeg == 99:
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] not in FixedSegList:
                        FixedSegList.append(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])  # cannot be moved!

            #---------- Actions depending of situation in cloud ----------
            if len(UplinkSegList) > 1:
                self.__HandleShortcut(CloudID,DesiredSegDict,FixedSegList)  # Shortcut !!
            else:
                if len(UplinkSegList) == 0 and isOnline:
                    print('++ Cloud seems to be w/o VPN Uplink(s):',self.__MeshCloudDict[CloudID]['CloudMembers'])
                    CheckSegList = ActiveSegList

                    for DestSeg in DesiredSegDict:
                        if DestSeg not in CheckSegList:
                            CheckSegList.append(DestSeg)

                    UplinkList = self.__NodeInfos.GetUplinkList(self.__MeshCloudDict[CloudID]['CloudMembers'],CheckSegList)
                    print('>> Uplink(s) found by Batman:',UplinkList)

                elif len(FixedSegList) > 0:
                    print('++ Fixed Cloud:',CloudID,'...')
#                    print('++ Fixed Cloud:',self.__MeshCloudDict[CloudID]['CloudMembers'])
                elif self.__MeshCloudDict[CloudID]['GluonType'] > 1:
                    self.__HandleSegmentAssignment(CloudID,DesiredSegDict,ActiveSegList)

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
            if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] is None and self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != '?') and
                (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][:3] == 'vpn' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['GluonType'] >= 2) and
                (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != 'vpn99')):

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] == 'auto' or self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] == 'fix ':
                    TargetSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']

                    if TargetSeg is None and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == 'vpn00':
                        TargetSeg = self.__DefaultTarget

                    if TargetSeg is not None:
                        if TargetSeg <= 8 or self.__NodeInfos.ffNodeDict[ffNodeMAC]['GluonType'] > 2:
                            if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                                if ffNodeMAC in self.__NodeMoveDict:
                                    print('!! Multiple Move:',ffNodeMAC,'->',TargetSeg)

                                self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                                print('>> git mv %s/peers/%s vpn%02d/peers/  = %s' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                                      TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8') ))

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == ' ':
                    print('++ Node seems to be w/o VPN Uplink:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],'/',ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'))
#                    CheckSegList = [ int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) ]
#
#                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is not None:
#                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] not in CheckSegList:
#                            CheckSegList.append(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])
#
#                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] is not None:
#                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] not in CheckSegList:
#                            CheckSegList.append(self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'])
#
#                    UplinkList = self.__NodeInfos.GetUplinkList([ffNodeMAC],CheckSegList)
#                    print('>> Uplink(s) found by Batman:',UplinkList)

            elif ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == '?' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] == 999) and
                  (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'] != '')):
                self.__NodeMoveDict[ffNodeMAC] = 999    # kill this Node

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "CheckConsistency"
    #
    #
    #-----------------------------------------------------------------------
    def __CheckConsistency(self):

        print('Checking Consistency of Data ...')

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != '?':

                if self.__NodeInfos.IsOnline(ffNodeMAC) and self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is None:
                    print('!! Segment is None:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))

                if self.__NodeInfos.IsOnline(ffNodeMAC) and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' and int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']:
                    print('!! KeyDir <> Segment:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],'<>',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == 'V' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == '':
                    print('!! Uplink w/o Key:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] = ' '

                if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] is not None and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '') and
                    (self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) and self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'] == 'auto')):
                    print('++ Wrong Segment:    ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]),'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is None and self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] is not None:
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] = self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']
                elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is None and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] = int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])


                #---------- calculate segment statistics ----------
                if self.__NodeInfos.IsOnline(ffNodeMAC):
                    ffSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']

                    if ffSeg in self.__GwInfos.Segments():
                        if not ffSeg in self.__SegmentDict:
                            self.__SegmentDict[ffSeg] = { 'Nodes':0, 'Clients':0, 'Uplinks':0 }

                        self.__SegmentDict[ffSeg]['Nodes'] += 1
                        self.__SegmentDict[ffSeg]['Clients'] += self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']

                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == 'V':
                            self.__SegmentDict[ffSeg]['Uplinks'] += 1
                    else:
                        print('>> Bad Segment:   ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',ffSeg)

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'] != '':
                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].strip().lower() != self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].strip().lower():
                            print('++ Hostname Mismatch:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'),
                                  '<-',self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].encode('utf-8'))

        print('... done.\n')
        return



    #==============================================================================
    # Method "CheckSegments"
    #
    #   Analysing Mesh Clouds for Segment Shortcuts
    #
    #==============================================================================
    def CheckSegments(self):

        self.__CreateMeshCloudList()
        self.__CheckMeshClouds()
        self.__CheckSingleNodes()

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

        NeighborOutFile = open(FileName, mode='w')
        NeighborOutFile.write('FFS-Mesh-Clouds on %s\n' % datetime.datetime.now())

        RegionDict = {}
        GluonMarker = [ '?', '%', '$', ' ' ]
        TotalMeshingNodes = 0

        for CloudID in sorted(self.__MeshCloudDict):

            TotalNodes    = 0
            TotalClients  = 0
            TotalUplinks  = 0
            OldGluon      = 0
            CurrentSeg    = None
            CurrentVPN    = None
            CurrentRegion = None
            CurrentZIP    = None
            CurrentError  = ''

            NeighborOutFile.write('\n------------------------------------------------------------------------------------------------------------------\n')
            TotalMeshingNodes += len(self.__MeshCloudDict[CloudID]['CloudMembers'])

            for ffnb in sorted(self.__MeshCloudDict[CloudID]['CloudMembers']):
                CurrentError = ' '

                if self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeInfos.ffNodeDict[ffnb]['Segment']

                    if CurrentSeg is None:
                        CurrentSeg = Segment
                    elif Segment != CurrentSeg:
#                        print('++ ERROR Segment:',ffnb,'=',CurrentSeg,'<>',Segment)
                        CurrentError = '!'

                    if CurrentRegion is None or CurrentRegion == '??':
                        CurrentRegion = self.__NodeInfos.ffNodeDict[ffnb]['Region']
                    elif self.__NodeInfos.ffNodeDict[ffnb]['Region'] != '??' and self.__NodeInfos.ffNodeDict[ffnb]['Region'] != CurrentRegion:
                        print('++ ERROR Region:',ffnb,'=',self.__NodeInfos.ffNodeDict[ffnb]['Region'],'<>',CurrentRegion)
                        CurrentError = '!'

                    if CurrentZIP is None:
                        CurrentZIP = self.__NodeInfos.ffNodeDict[ffnb]['ZIP']

                if CurrentError == ' ' and self.__NodeInfos.ffNodeDict[ffnb]['SegMode'] != 'auto':
                    CurrentError = '+'

                if CurrentError == ' ' and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':
                    if ((self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is not None and int(self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffnb]['Segment']) or
                        (self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] is not None and self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != self.__NodeInfos.ffNodeDict[ffnb]['Segment'])):
                        print('++ ERROR Region:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,'=',self.__NodeInfos.ffNodeDict[ffnb]['Name'].encode('UTF-8'),'->',
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

                NeighborOutFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = %s (%s = %s)\n' % (CurrentError,self.__NodeInfos.ffNodeDict[ffnb]['Status'],Segment,
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Clients'],ffnb,self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['KeyFile'],self.__NodeInfos.ffNodeDict[ffnb]['Name'].encode('UTF-8'),
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],self.__NodeInfos.ffNodeDict[ffnb]['Region']))
                if self.__NodeInfos.IsOnline(ffnb):
                    TotalNodes   += 1
                    TotalClients += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                if self.__NodeInfos.ffNodeDict[ffnb]['Status'] == 'V':
                    TotalUplinks += 1

                if self.__NodeInfos.ffNodeDict[ffnb]['GluonType'] < 3:
                    OldGluon += 1

            NeighborOutFile.write('\n          Total Online-Nodes / Clients / Uplinks = %3d / %3d / %3d   (%s)\n' % (TotalNodes,TotalClients,TotalUplinks,CurrentRegion))

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
        NeighborOutFile.write('\nSum: %d Clouds with %d Nodes\n' % (len(self.__MeshCloudDict),TotalMeshingNodes))

        print('\nWriting out Single Nodes ...')

        NeighborOutFile.write('\n\n########################################################################\n\n')
        NeighborOutFile.write('Single Nodes:\n\n')

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

                NeighborOutFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = %s (%s = %s)\n' % (CurrentError,self.__NodeInfos.ffNodeDict[ffnb]['Status'],
                                                                                                Segment,self.__NodeInfos.ffNodeDict[ffnb]['Clients'],ffnb,
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],self.__NodeInfos.ffNodeDict[ffnb]['KeyFile'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Name'].encode('UTF-8'),self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Region']))
                TotalNodes   += 1
                TotalClients += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                Region = self.__NodeInfos.ffNodeDict[ffnb]['Region']

                if Region not in RegionDict:
#                    RegionDict[Region] = { 'Nodes':1, 'Clients':self.__NodeInfos.ffNodeDict[ffnb]['Clients'], 'OldGluon':0, 'Segment':self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] }
                    RegionDict[Region] = { 'Nodes':1, 'Clients':self.__NodeInfos.ffNodeDict[ffnb]['Clients'], 'OldGluon':0, 'Segment':self.__NodeInfos.ffNodeDict[ffnb]['Segment'] }
                else:
                    RegionDict[Region]['Nodes']   += 1
                    RegionDict[Region]['Clients'] += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                if self.__NodeInfos.ffNodeDict[ffnb]['GluonType'] < 3:
                    RegionDict[Region]['OldGluon'] += 1

        print('\nWrite out Statistics ...')

        NeighborOutFile.write('\n\n########################################################################\n\n')
        NeighborOutFile.write('Online-Nodes      / Clients / Sum:\n\n')

        TotalNodes   = 0
        TotalClients = 0
        TotalUplinks = 0

        for ffSeg in sorted(self.__SegmentDict):
            NeighborOutFile.write('Segment %02d: %5d / %5d / %5d\n' % (ffSeg, self.__SegmentDict[ffSeg]['Nodes'], self.__SegmentDict[ffSeg]['Clients'], self.__SegmentDict[ffSeg]['Nodes']+self.__SegmentDict[ffSeg]['Clients']))
            TotalNodes   += self.__SegmentDict[ffSeg]['Nodes']
            TotalClients += self.__SegmentDict[ffSeg]['Clients']
#            TotalUplinks += self.__SegmentDict[ffSeg]['Uplinks']


        NeighborOutFile.write('\n------------------------------------------------------------------------\n')
        NeighborOutFile.write('Totals:     %5d / %5d / %5d\n' % (TotalNodes, TotalClients, TotalNodes+TotalClients))


        NeighborOutFile.write('\n\n########################################################################\n\n')
        NeighborOutFile.write('Stress of Regions:\n\n')

        TotalNodes   = 0
        TotalClients = 0

        for Region in sorted(RegionDict):
            NeighborOutFile.write('%-32s: %4d + %4d = %4d  (Seg.%02d / old = %2d)\n' % (Region, RegionDict[Region]['Nodes'], RegionDict[Region]['Clients'], RegionDict[Region]['Nodes']+RegionDict[Region]['Clients'], RegionDict[Region]['Segment'], RegionDict[Region]['OldGluon']))
            TotalNodes   += RegionDict[Region]['Nodes']
            TotalClients += RegionDict[Region]['Clients']

        NeighborOutFile.write('\n------------------------------------------------------------------------\n')
        NeighborOutFile.write('Totals:     %5d / %5d / %5d\n' % (TotalNodes, TotalClients, TotalNodes+TotalClients))

        NeighborOutFile.close()
        print()
        return
