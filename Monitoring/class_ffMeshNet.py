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

from class_ffNodeInfo import *
from class_ffGatewayInfo import *



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

RegionSegDict = {
    'Alb-Donau-Kreis':'vpn02',
    'Bayern':'vpn02',
    'Biberach':'vpn02',
    'Bodenseekreis':'vpn02',
    'Boeblingen':'vpn04',
    'Calw':'vpn04',
    'Esslingen':'vpn02',
    'Frankreich':'vpn04',
    'Goeppingen':'vpn03',
    'Heilbronn':'vpn04',
    'Hessen':'vpn04',
    'Hohenlohekreis':'vpn03',
    'Karlsruhe':'vpn04',
    'Konstanz':'vpn02',
    'Ludwigsburg':'vpn04',
    'Mecklenburg-Vorpommern':'vpn03',
    'Neckar-Odenwald-Kreis':'vpn04',
    'Nordrhein-Westfalen':'vpn04',
    'Ortenaukreis':'vpn04',
    'Ostalbkreis':'vpn03',
    'Pforzheim':'vpn04',
    'Rastatt':'vpn04',
    'Ravensburg':'vpn02',
    'Rems-Murr-Kreis':'vpn03',
    'Reutlingen':'vpn02',
    'Rheinland-Pfalz':'vpn04',
    'Rottweil':'vpn04',
    'Schwaebisch-Hall':'vpn03',
    'Schwarzwald-Baar-Kreis':'vpn04',
    'Sigmaringen':'vpn02',
    'Stuttgart':'vpn01',
    'Tuebingen':'vpn02',
    'Zollernalbkreis':'vpn02'
}




class ffMeshNet:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,NodeInfos,GwInfos):

        # private Attributes
        self.__NodeInfos = NodeInfos
        self.__GwInfos = GwInfos

        self.__MeshCloudDict = {}       # Dictionary of Mesh-Clouds with List of Member-Nodes
        self.__SegmentDict = {}         # Dictionary of Segments with their Number of Nodes and Clients
        self.__NodeMoveDict = {}        # Git Moves of Nodes from one Segment to another

        return



    #-----------------------------------------------------------------------
    # private function "__AddNeighbour2Cloud"
    #
    #   Add Nodes to Mesh-Cloud-List
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

        print('\nNumber of Clouds / Nodes / Clients:',len(self.__MeshCloudDict),'/',TotalNodes,'/',TotalClients)
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
                    print(self.__NodeInfos.ffNodeDict[ffNodeMAC])
                    print()

        return


    #-----------------------------------------------------------------------
    # private function "__HandleShortcut"
    #
    #   Handle Segment Shortcut
    #
    #-----------------------------------------------------------------------
    def __HandleShortcut(self,CloudID,ActiveSegDict,DesiredSegDict,FixedSegList):

        CommonSegList = []
        SegWeight = 0
        TargetSeg = 99;   # 99 = unknown

        if len(FixedSegList) > 0:
            if len(FixedSegList) > 1:
                print('!! ALARM - Multiple Segments with fixed Nodes:',FixedSegList,self.__MeshCloudDict[CloudID])

            else:   #----- exactly one Segment with fixed Nodes
                for Segment in FixedSegList:
                    TargetSeg = Segment

        else:   #----- No fixed Nodes -----
            for Segment in ActiveSegDict.keys():
                if Segment in DesiredSegDict:
                    CommonSegList.append(Segment)

            if len(CommonSegList) > 0:
                for Segment in CommonSegList:
                    if ActiveSegDict[Segment] > SegWeight:
                        SegWeight = ActiveSegDict[Segment]
                        TargetSeg = Segment

            else:
                for Segment in DesiredSegDict.keys():
                    if DesiredSegDict[Segment] > SegWeight:
                        SegWeight = DesiredSegDict[Segment]
                        TargetSeg = Segment

        if TargetSeg < 99:
            self.__MoveNodesInCloud(CloudID,TargetSeg)

        return


    #-----------------------------------------------------------------------
    # private function "__HandleGeoLocation"
    #
    #   Handling Geo-Location (Segments) of Mesh Clouds
    #
    #-----------------------------------------------------------------------
    def __HandleGeoLocation(self,CloudID,ActiveSegDict,DesiredSegDict):

        SegWeight = 0
        TargetSeg = 99;   # 99 = unknown

        if len(DesiredSegDict) == 0:
            # Check for Legacy Nodes only
            if 0 in ActiveSegDict:
                SegWeight = 9999

                for Segment in self.__SegmentDict.keys():
                    if Segment > 0:
                        if (self.__SegmentDict[Segment]['Nodes'] + self.__SegmentDict[Segment]['Clients']) < SegWeight:
                            SegWeight = self.__SegmentDict[Segment]['Nodes'] + self.__SegmentDict[Segment]['Clients']
                            TargetSeg = Segment
        else:
            for Segment in DesiredSegDict.keys():
                if DesiredSegDict[Segment] > SegWeight:
                    SegWeight = DesiredSegDict[Segment]
                    TargetSeg = Segment

        if TargetSeg < 99:
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
                ActiveSegDict = {}
                DesiredSegDict = {}
                FixedSegList = []

                for ffNodeMAC in self.__MeshCloudDict[CloudID]['CloudMembers']:

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                        VpnSeg = int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])

                        if not VpnSeg in ActiveSegDict:
                            ActiveSegDict[VpnSeg] = 1 + self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']
                        else:
                            ActiveSegDict[VpnSeg] += 1 + self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']
                    else:
                        if not self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] in ActiveSegDict:
                            ActiveSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']] = 1 + self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']
                        else:
                            ActiveSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']] += 1 + self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != 99:
                        if not self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] in DesiredSegDict:
                            DesiredSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']] =  1 + self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']
                        else:
                            DesiredSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']] += 1 + self.__NodeInfos.ffNodeDict[ffNodeMAC]['Clients']

                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] != 'auto':
                        if not self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] in FixedSegList:
                            FixedSegList.append(self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])

                        if self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '':
                            VpnSeg = int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:])

                            if not VpnSeg in FixedSegList:
                                FixedSegList.append(VpnSeg)

                if len(ActiveSegDict) > 1:
                    self.__HandleShortcut(CloudID,ActiveSegDict,DesiredSegDict,FixedSegList)
                else:
                    if len(ActiveSegDict) == 0:
                        print('!! No VPN Uplink:',self.__MeshCloudDict[CloudID]['CloudMembers'])
                        
                    if len(FixedSegList) == 0:
                        self.__HandleGeoLocation(CloudID,ActiveSegDict,DesiredSegDict)
                    else:
                        print('++ Fixed Cloud:',self.__MeshCloudDict[CloudID]['CloudMembers'])
                        
        print('... done.')
        print()
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
                (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] == 'auto')):

                SegWeight = 9999
                TargetSeg = self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']

                if TargetSeg == 99 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] == 'vpn00':

                    for Segment in self.__SegmentDict.keys():
                        if Segment > 0:
                            if (self.__SegmentDict[Segment]['Nodes'] + self.__SegmentDict[Segment]['Clients']) < SegWeight:
                                SegWeight = self.__SegmentDict[Segment]['Nodes'] + self.__SegmentDict[Segment]['Clients']
                                TargetSeg = Segment

                if TargetSeg < 99:
                    if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != TargetSeg:
                        if ffNodeMAC in self.__NodeMoveDict:
                            print('!! Multiple Move:',ffNodeMAC,'->',TargetSeg)

                        self.__NodeMoveDict[ffNodeMAC] = TargetSeg
                        print('>> git mv %s/peers/%s vpn%02d/peers/  = %s'%( self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                             TargetSeg,self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8') ))

        print('... done.')
        print()
        return



    #-----------------------------------------------------------------------
    # private function "CheckConsistency"
    #
    #
    #-----------------------------------------------------------------------
    def __CheckConsistency(self):

        print('Check Consistency of Data ...')

        ffSegmentList = self.__GwInfos.Segments()

        for ffNodeMAC in self.__NodeInfos.ffNodeDict.keys():
            if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'] != '?':

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'] is None:
                    print('!! Segment is None:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('UTF-8'))
                elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'] != '' and self.__NodeInfos.IsOnline(ffNodeMAC):
                    if int(self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'][3:]) != self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']:
                        print('!! KeyDir doesn\'t match Segment:',ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'],'<>',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'])

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != 99 and self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment']:
                    print('++ Wrong Segment:   ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])
                elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'][:4] != 'auto':
                    print('++ Segment Assign:  ',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Segment'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])

                if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region'] in RegionSegDict:
                    if int(RegionSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region']][3:]) != self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg']:
                        print('++ DestSeg Mismatch:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',int(RegionSegDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region']][3:]),'<>',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])
                elif self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region'] != '??' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region'] != 'No Location' and self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'] != 99:
                    print('++ Missing Region:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Region'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['DestSeg'],self.__NodeInfos.ffNodeDict[ffNodeMAC]['SegMode'])

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
                    if self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].lower() != self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].lower():
                        print('++ Hostname Mismatch:',self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],'->',self.__NodeInfos.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'),
                              '<-',self.__GwInfos.FastdKeyDict[self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile']]['PeerName'].encode('utf-8'))

        print('... done.')
        print()
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

        self.__NodeInfos.AddNeighbours()
        self.__CheckConsistency()
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
    # Method "WriteMoveList"
    #
    #   Write out Node-Moves
    #==============================================================================
    def WriteMoveList(self,FileName):

        print('Write out Node-Moves ...')
        NodeMoveFile = open(FileName, mode='w')

        for ffNodeMAC in sorted(self.__NodeMoveDict):
            NodeMoveFile.write('git mv %s/peers/%s vpn%02d/peers/\n' % (self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyDir'], self.__NodeInfos.ffNodeDict[ffNodeMAC]['KeyFile'],
                                                                        self.__NodeMoveDict[ffNodeMAC]))

        NodeMoveFile.close()
        print('... done.\n')
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

                    NeighborOutFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = %s (%s = %s)\n' % (CurrentError,self.__NodeInfos.ffNodeDict[ffnb]['Status'],self.__NodeInfos.ffNodeDict[ffnb]['Segment'],
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

                NeighborOutFile.write('%s%s Seg.%02d [%3d] %s = %5s - %16s = %s (%s = %s)\n' % (CurrentError,self.__NodeInfos.ffNodeDict[ffnb]['Status'],
                                                                                                self.__NodeInfos.ffNodeDict[ffnb]['Segment'],self.__NodeInfos.ffNodeDict[ffnb]['Clients'],ffnb,
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

