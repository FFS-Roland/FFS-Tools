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
import fcntl

from class_ffNodeInfo import *
from class_ffGatewayInfo import *



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

StatFileName   = 'SegStatistics.json'

MaxStatisticsData  = 12 * 24 * 7    # 1 Week wit Data all 5 Minutes


RegionSegDict = {
    'Stuttgart':'vpn01',

    'Alb-Donau-Kreis':'vpn02',
    'Bayern':'vpn02',
    'Biberach':'vpn02',
    'Bodenseekreis':'vpn02',
    'Konstanz':'vpn02',
    'Ravensburg':'vpn02',
    'Reutlingen':'vpn02',
    'Sigmaringen':'vpn02',
    'Tuebingen':'vpn02',
    'Zollernalbkreis':'vpn02',

    'Hohenlohekreis':'vpn03',
    'Mecklenburg-Vorpommern':'vpn03',
    'Ostalbkreis':'vpn03',
    'Schwaebisch-Hall':'vpn03',

    'Calw':'vpn04',
    'Frankreich':'vpn04',
    'Heilbronn':'vpn04',
    'Hessen':'vpn04',
    'Karlsruhe':'vpn04',
    'Ludwigsburg':'vpn04',
    'Neckar-Odenwald-Kreis':'vpn04',
    'Nordrhein-Westfalen':'vpn04',
    'Ortenaukreis':'vpn04',
    'Pforzheim':'vpn04',
    'Rastatt':'vpn04',
    'Rheinland-Pfalz':'vpn04',
    'Rottweil':'vpn04',
    'Saarland':'vpn04',
    'Schwarzwald-Baar-Kreis':'vpn04',

    'Esslingen':'vpn05',
    'Goeppingen':'vpn05',

    'Boeblingen':'vpn06',

    'Rems-Murr-Kreis':'vpn07'
}


NoRegionList = [ '??','No Location','Outside' ]




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
        self.__GwInfos = GwInfos

        self.__MeshCloudDict = {}       # Dictionary of Mesh-Clouds with List of Member-Nodes
        self.__SegmentDict   = {}       # Segment Data: { 'Nodes','Clients','Uplinks','Weight' }
        self.__NodeMoveDict  = {}       # Git Moves of Nodes from one Segment to another

        self.__DefaultTarget = 8        # Target Segment to use if no better Data available

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

        if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Status'] != '?' and not ffNeighbourMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:

            if self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] == 0:
                self.__MeshCloudDict[CloudID]['NumNodes'] += 1
                self.__MeshCloudDict[CloudID]['NumClients'] += self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Clients']
                self.__MeshCloudDict[CloudID]['CloudMembers'].append(ffNeighbourMAC)
                self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] = CloudID

                for MeshMAC in self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Neighbours']:
                    if MeshMAC in self.__NodeInfos.MAC2NodeIDDict:
    #                    print('+',Cloud,MAC2NodeIDDict[MeshMAC])
                        self.__AddNeighbour2Cloud(CloudID,self.__NodeInfos.MAC2NodeIDDict[MeshMAC])
                    else:
                        print('!! Unknown Neighbour',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Segment'],'-',ffNeighbourMAC,'=',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name'].encode('UTF-8'),'->',MeshMAC)
            elif self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud'] == CloudID:
                print('!! Cloud inconsistent:',CloudID,'-',ffNeighbourMAC,'=',self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['Name'].encode('UTF-8'),'->',self.__MeshCloudDict[CloudID]['CloudMembers'])
            else:
                # Node is already part of another Mesh Cloud -> merge Clouds
                oldCloudID = self.__NodeInfos.ffNodeDict[ffNeighbourMAC]['InCloud']
    #            print('++ Merging Clouds:',ffNeighbourMAC,'=',ffNodeDict[ffNeighbourMAC]['Name'].encode('UTF-8'),oldCloudID,'->',CloudID)

                self.__MeshCloudDict[CloudID]['NumNodes']   += self.__MeshCloudDict[oldCloudID]['NumNodes']
                self.__MeshCloudDict[CloudID]['NumClients'] += self.__MeshCloudDict[oldCloudID]['NumClients']

                for ffNodeMAC in self.__MeshCloudDict[oldCloudID]['CloudMembers']:
                    self.__MeshCloudDict[CloudID]['CloudMembers'].append(ffNodeMAC)

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
        CloudNumber = 0
        TotalNodes = 0
        TotalClients = 0

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if len(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Neighbours']) > 0 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] == 0:
                CloudNumber += 1

                self.__MeshCloudDict[CloudNumber] = {
                    'NumNodes':0,
                    'NumClients':0,
                    'CloudMembers':[]
                }

                self.__AddNeighbour2Cloud(CloudNumber,ffNodeMAC)

        for CloudID in self.__MeshCloudDict:
            if self.__MeshCloudDict[CloudID]['NumNodes'] < 2:
                for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] = 0
    #                print('++ Single-Node Cloud:',CloudID,'-',ffNodeMAC,'=',ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))

                self.__MeshCloudDict[CloudID]['NumNodes'] = 0
                self.__MeshCloudDict[CloudID]['NumClients'] = 0
            else:
                TotalNodes   += self.__MeshCloudDict[CloudID]['NumNodes']
                TotalClients += self.__MeshCloudDict[CloudID]['NumClients']
    #            print(CloudID,MeshCloudDict[CloudID]['NumNodes'],MeshCloudDict[CloudID]['Segments'])

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

                    self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                    print('>> git mv %s/peers/%s vpn%02d/peers/  = %s'%( self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                         TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8') ))
#                    print(self.__NodeInfos.ffNodeDict[ffNodeMAC])
                    print()

        return



    #-----------------------------------------------------------------------
    # private function "__HandleShortcut"
    #
    #   Handle Segment Shortcut
    #
    #-----------------------------------------------------------------------
    def __HandleShortcut(self,CloudID,UplinkSegList,DesiredSegDict,FixedSegList):

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
            for Segment in UplinkSegList:
                if Segment in DesiredSegDict:
                    if DesiredSegDict[Segment] > SegWeight:
                        SegWeight = DesiredSegDict[Segment]
                        TargetSeg = Segment

        if TargetSeg is not None:
            self.__MoveNodesInCloud(CloudID,TargetSeg)
            self.__alert('!! Shortcut detected !!!')
            print(self.__MeshCloudDict[CloudID]['CloudMembers'])
            print()

        return



    #-----------------------------------------------------------------------
    # private function "__HandleGeoLocation"
    #
    #   Handling Geo-Location (Segments) of Mesh Cloud w/o shortcuts or fixes
    #
    #-----------------------------------------------------------------------
    def __HandleGeoLocation(self,CloudID,ActiveSegDict,DesiredSegDict):

        SegWeight = 0
        TargetSeg = None

        if len(DesiredSegDict) == 0:
            if 0 in ActiveSegDict:  # Cloud in Legacy Segment
                TargetSeg = self.__DefaultTarget

        else:
            for Segment in DesiredSegDict.keys():
                if DesiredSegDict[Segment] > SegWeight:
                    SegWeight = DesiredSegDict[Segment]
                    TargetSeg = Segment

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
            if self.__MeshCloudDict[CloudID]['NumNodes'] > 1:
                ActiveSegDict  = {}    # really used segments with number of nodes
                DesiredSegDict = {}    # desired segments with number of nodes
                UplinkSegList  = []    # List of segments from nodes with uplink
                FixedSegList   = []    # List of segments from nodes with fixed segment assignment

                #---------- Analysing used segments with their nodes and clients ----------
                for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] not in ActiveSegDict:
                        ActiveSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']] = 1
                    else:
                        ActiveSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']] += 1

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == 'V' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                        VpnSeg = int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])

                        if VpnSeg not in UplinkSegList:
                            UplinkSegList.append(VpnSeg)

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != 99:
                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] not in DesiredSegDict:
                            DesiredSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']] =  1
                        else:
                            DesiredSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']] += 1

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] != 'auto' or self.__NodeInfos.ffNodeDict[ffNodeMAC]['oldGluon'] == '%':
                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] not in FixedSegList:
                            FixedSegList.append(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])

                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                            VpnSeg = int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])

                            if VpnSeg not in FixedSegList:
                                FixedSegList.append(VpnSeg)

                #---------- Actions depending of situation in cloud ----------
                if len(UplinkSegList) > 1:
                    self.__HandleShortcut(CloudID,UplinkSegList,DesiredSegDict,FixedSegList)
                else:
                    if len(UplinkSegList) == 0 :
                        print('++ No VPN Uplink:',self.__MeshCloudDict[CloudID]['CloudMembers'])
                    elif len(FixedSegList) > 0:
                        print('++ Fixed Cloud:',self.__MeshCloudDict[CloudID]['CloudMembers'])
                    else:
                        self.__HandleGeoLocation(CloudID,ActiveSegDict,DesiredSegDict)

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__CheckSingleNodes"
    #
    #   Analysing Mesh Clouds for Segment Shortcuts
    #
    #-----------------------------------------------------------------------
    def __CheckSingleNodes(self):

        print('Checking Single Nodes ...')

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['InCloud'] == 0 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != '?') and
                (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] == 'auto') and
                (self.__NodeInfos.ffNodeDict[ffNodeMAC]['oldGluon'] != '%')):

                TargetSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']

#                if TargetSeg == 99 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == 'vpn00':
                if TargetSeg == 99 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == 'vpn01':
                    TargetSeg = self.__DefaultTarget

                if TargetSeg < 99:
                    if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                        if ffNodeMAC in self.__NodeMoveDict:
                            print('!! Multiple Move:',ffNodeMAC,'->',TargetSeg)

                        self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                        print('>> git mv %s/peers/%s vpn%02d/peers/  = %s'%( self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                             TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8') ))

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "CheckConsistency"
    #
    #
    #-----------------------------------------------------------------------
    def __CheckConsistency(self):

        print('\nCheck Consistency of Data ...')

        ffSegmentList = self.__GwInfos.Segments()

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != '?':

                if ((self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' or self.__NodeInfos.IsOnline(ffNodeMAC)) and
                    (self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is None)):
                    print('!! Segment is None:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' and int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']:
                    print('!! KeyDir <> Segment:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],'<>',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == 'V' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == '':
                    print('!! Uplink w/o Key:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] = ' '

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region'] in RegionSegDict:
                    if int(RegionSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region']][3:]) != self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']:
                        print('++ DestSeg Mismatch: ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],'->',int(RegionSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region']][3:]),self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])
                        self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] = int(RegionSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region']][3:])  # Region has priority
                elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region'] in NoRegionList:
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] = 99
                else:
                    self.__alert('++ Invalid Region: '+self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status']+' '+ffNodeMAC+' = '+self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region']+' -> vpn'+self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'])
                    self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] = 99

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != 99 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']:
                    print('++ Wrong Segment:    ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])


                #---------- calculate segment statistics ----------
                if self.__NodeInfos.IsOnline(ffNodeMAC):
                    ffSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']

                    if ffSeg in self.__GwInfos.Segments():
                        if not ffSeg in self.__SegmentDict:
                            self.__SegmentDict[ffSeg] = { 'Nodes':0, 'Clients':0, 'Uplinks':0, 'Weight':9999 }

                        self.__SegmentDict[ffSeg]['Nodes'] += 1
                        self.__SegmentDict[ffSeg]['Clients'] += self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']

                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] == 'V':
                            self.__SegmentDict[ffSeg]['Uplinks'] += 1
                    else:
                        print('>> Bad Segment:   ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',ffSeg)

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'] != '':
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].lower() != self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].lower():
                        print('++ Hostname Mismatch:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'),
                              '<-',self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].encode('utf-8'))

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__SetSegmentWeight"
    #
    #   Set Weight of Segment (Average Sum of Nodes + Clients)
    #
    # __SegmentDict[Segment][Weight]
    #-----------------------------------------------------------------------
    def __SetSegmentWeight(self):

        print('Set Segment weight ...')
        SegWeight = 9999

        for Segment in self.__SegmentDict.keys():
            if self.__SegmentDict[Segment]['Weight'] is None:
                self.__SegmentDict[Segment]['Weight'] = self.__SegmentDict[Segment]['Nodes'] + self.__SegmentDict[Segment]['Clients']

            if Segment > 0 and Segment < 9:  #....................................... must be changed later !!
                if self.__SegmentDict[Segment]['Weight'] < SegWeight:
                    SegWeight = self.__SegmentDict[Segment]['Weight']
#                    self.__DefaultTarget = Segment

        print('... Default Target =',self.__DefaultTarget)

        return



    #==============================================================================
    # Method "MergeData"
    #
    #   Merging Data from Gateways (fastd-Keys) to Nodes
    #
    #==============================================================================
    def MergeData(self):

        for KeyIndex in self.__GwInfos.FastdKeyDict.keys():
            self.__NodeInfos.AddNode(KeyIndex,self.__GwInfos.FastdKeyDict[KeyIndex])

        self.__CheckConsistency()
        return



    #==============================================================================
    # Method "UpdateStatistikDB"
    #
    #   Write updates Statistik-json
    #==============================================================================
    def UpdateStatistikDB(self,Path):

        print('Update Statistik-DB ...')
        StatisticsJsonDict = {}
        StatisticsJsonName = os.path.join(Path,StatFileName)

        try:
            LockFile = open('/tmp/.SegStatistics.lock', mode='w+')
            fcntl.lockf(LockFile,fcntl.LOCK_EX)

            if os.path.exists(StatisticsJsonName):
                print('... reading Statistics-DB from Json File ...')
                StatisticsJsonFile = open(StatisticsJsonName, mode='r')
                StatisticsJsonDict = json.load(StatisticsJsonFile)
                StatisticsJsonFile.close()
            else:
                StatisticsJsonDict = {}

            print('... updateing statistics ...')
            for Segment in self.__SegmentDict.keys():
                JsonSegIdx = str(Segment)

                if JsonSegIdx not in StatisticsJsonDict:
                    StatisticsJsonDict[JsonSegIdx] = { 'Sum':0, 'Count':0 }

                StatisticsJsonDict[JsonSegIdx]['Sum']   += self.__SegmentDict[Segment]['Nodes']+self.__SegmentDict[Segment]['Clients']
                StatisticsJsonDict[JsonSegIdx]['Count'] += 1

                if StatisticsJsonDict[JsonSegIdx]['Count'] > MaxStatisticsData:
                    StatisticsJsonDict[JsonSegIdx]['Sum']   -= int(StatisticsJsonDict[JsonSegIdx]['Sum']/StatisticsJsonDict[JsonSegIdx]['Count'])
                    StatisticsJsonDict[JsonSegIdx]['Count'] -= 1

                self.__SegmentDict[Segment]['Weight'] = int(StatisticsJsonDict[JsonSegIdx]['Sum']/StatisticsJsonDict[JsonSegIdx]['Count'])

            print('... writing Statistics-DB as json-File ...')

            StatisticsJsonFile = open(StatisticsJsonName, mode='w+')
            json.dump(StatisticsJsonDict,StatisticsJsonFile)
            StatisticsJsonFile.close()

        except:
            self.__alert('\n!! Error on Updating Statistics Databases as json-File!')

        finally:
            fcntl.lockf(LockFile,fcntl.LOCK_UN)
            LockFile.close()

        print('... done.\n')
        return



    #==============================================================================
    # Method "CheckSegments"
    #
    #   Analysing Mesh Clouds for Segment Shortcuts
    #
    #==============================================================================
    def CheckSegments(self):

        self.__SetSegmentWeight()
        self.__CreateMeshCloudList()
        self.__CheckMeshClouds()
        self.__CheckSingleNodes()
        return



    #==============================================================================
    # Method "WriteMoveList"
    #
    #   Write out Node-Moves
    #==============================================================================
    def WriteMoveList(self,FileName):

        if len(self.__NodeMoveDict) > 0:
            if self.AnalyseOnly or self.__NodeInfos.AnalyseOnly or self.__GwInfos.AnalyseOnly:
                self.__alert('!! There might be Nodes to be moved but cannot due to inconsistent Data!')
            else:
                self.__alert('++ There are Nodes to be moved:')
                NodeMoveFile = open(FileName, mode='w')

                for ffNodeMAC in sorted(self.__NodeMoveDict):
                    MoveElement = 'git mv %s/peers/%s vpn%02d/peers/\n' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'], self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],self.__NodeMoveDict[ffNodeMAC])

                    NodeMoveFile.write(MoveElement)
                    self.__alert('   '+MoveElement)

                NodeMoveFile.close()
                print('... done.\n')

        elif os.path.exists(FileName):
            os.remove(FileName)
            print('... MoveList deleted.')

        return



    #==============================================================================
    # Method "WriteMeshCloudList"
    #
    #   Write out Mesh Cloud List
    #==============================================================================
    def WriteMeshCloudList(self,FileName):

        print('Writing out Mesh Cloud List ...')

        NeighborOutFile = open(FileName, mode='w')
        NeighborOutFile.write('FFS-Mesh-Clouds on %s\n' % datetime.datetime.now())

        TotalMeshingNodes = 0

        for CloudID in sorted(self.__MeshCloudDict):
            if self.__MeshCloudDict[CloudID]['NumNodes'] > 1:

                TotalNodes    = 0
                TotalClients  = 0
                TotalUplinks  = 0
                CurrentSeg    = -1
                CurrentVPN    = ''
                CurrentError  = ''

                NeighborOutFile.write('\n------------------------------------------------------------------------------------------------------------------\n')
                TotalMeshingNodes += self.__MeshCloudDict[CloudID]['NumNodes']

                for ffnb in sorted(self.__MeshCloudDict[CloudID]['CloudMembers']):
                    CurrentError = ' '

                    if CurrentSeg < 0:
                        CurrentSeg = self.__NodeInfos.ffNodeDict[ffnb]['Segment']
                    elif self.__NodeInfos.ffNodeDict[ffnb]['Segment'] != CurrentSeg:
        #                print('++ ERROR Segment:',ffnb,'=',CurrentSeg,'<>',ffNodeDict[ffnb]['Segment'])
                        CurrentError = '!'

                    if self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':
                        if ((int(self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffnb]['Segment']) or
                            (self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != 99 and self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != self.__NodeInfos.ffNodeDict[ffnb]['Segment'])):
                            print('++ ERROR Region:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],self.__NodeInfos.ffNodeDict[ffnb]['Segment'],'->',
                                  self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],self.__NodeInfos.ffNodeDict[ffnb]['SegMode'])
                            CurrentError = '>'

                    if CurrentVPN == '' and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':
                        CurrentVPN = self.__NodeInfos.ffNodeDict[ffnb]['KeyDir']
                    elif CurrentVPN != '' and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '' and self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != CurrentVPN:
                        print('++ ERROR KeyDir:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,'=',CurrentVPN,'<>',self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'])
                        CurrentError = '*'

                    if self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is None:
                        Segment = 99
                    else:
                    	Segment = self.__NodeInfos.ffNodeDict[ffnb]['Segment']

                    NeighborOutFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = %s (%s = %s)\n' % (CurrentError,self.__NodeInfos.ffNodeDict[ffnb]['Status'],Segment,
                                                                                                    self.__NodeInfos.ffNodeDict[ffnb]['Clients'],ffnb,self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],
                                                                                                    self.__NodeInfos.ffNodeDict[ffnb]['KeyFile'],self.__NodeInfos.ffNodeDict[ffnb]['Name'].encode('UTF-8'),
                                                                                                    self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],self.__NodeInfos.ffNodeDict[ffnb]['Region']))
                    TotalNodes   += 1
                    TotalClients += self.__NodeInfos.ffNodeDict[ffnb]['Clients']

                    if self.__NodeInfos.ffNodeDict[ffnb]['Status'] == 'V':
                        TotalUplinks += 1

                NeighborOutFile.write('\n         Total Nodes / Clients / Uplinks = %3d / %3d / %3d\n' % (TotalNodes,TotalClients,TotalUplinks))

        print('\nWriting out Single Nodes ...')

        NeighborOutFile.write('\n\n########################################################################\n\n')
        NeighborOutFile.write('Single Nodes:\n\n')

        for ffnb in sorted(self.__NodeInfos.ffNodeDict.keys()):
            if self.__NodeInfos.ffNodeDict[ffnb]['InCloud'] == 0 and self.__NodeInfos.IsOnline(ffnb):

                CurrentError = ' '

                if self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'] != '':
                    if ((int(self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffnb]['Segment']) or
                        (self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != 99 and self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'] != self.__NodeInfos.ffNodeDict[ffnb]['Segment'])):
                        print('++ ERROR Region:',self.__NodeInfos.ffNodeDict[ffnb]['Status'],ffnb,self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],
                              self.__NodeInfos.ffNodeDict[ffnb]['Segment'],'->',self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],self.__NodeInfos.ffNodeDict[ffnb]['SegMode'])
                        CurrentError = '>'

                if self.__NodeInfos.ffNodeDict[ffnb]['Segment'] is None:
                    Segment = 99
                else:
                    Segment = self.__NodeInfos.ffNodeDict[ffnb]['Segment']

                NeighborOutFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = %s (%s = %s)\n' % (CurrentError,self.__NodeInfos.ffNodeDict[ffnb]['Status'],
                                                                                                Segment,self.__NodeInfos.ffNodeDict[ffnb]['Clients'],ffnb,
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['KeyDir'],self.__NodeInfos.ffNodeDict[ffnb]['KeyFile'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Name'].encode('UTF-8'),self.__NodeInfos.ffNodeDict[ffnb]['DestSeg'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Region']))
                TotalNodes   += 1
                TotalClients += self.__NodeInfos.ffNodeDict[ffnb]['Clients']


        print('\nWrite out Statistics ...')

        NeighborOutFile.write('\n\n########################################################################\n\n')
        NeighborOutFile.write('Online-Nodes / Clients / Uplinks in Segments:\n\n')

        TotalNodes   = 0
        TotalClients = 0
        TotalUplinks = 0

        for ffSeg in sorted(self.__SegmentDict):
            NeighborOutFile.write('Segment %02d: %5d / %5d / %5d\n' % (ffSeg, self.__SegmentDict[ffSeg]['Nodes'], self.__SegmentDict[ffSeg]['Clients'], self.__SegmentDict[ffSeg]['Uplinks']))
            TotalNodes   += self.__SegmentDict[ffSeg]['Nodes']
            TotalClients += self.__SegmentDict[ffSeg]['Clients']
            TotalUplinks += self.__SegmentDict[ffSeg]['Uplinks']


        NeighborOutFile.write('\n\n------------------------------------------------------------------------\n\n')
        NeighborOutFile.write('Totals:     %5d / %5d / %5d / %5d\n' % (TotalNodes, TotalMeshingNodes, TotalClients, TotalUplinks))

        NeighborOutFile.close()
        print()
        return
