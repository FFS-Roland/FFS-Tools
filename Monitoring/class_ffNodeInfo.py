#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  class_ffNodeInfo.py                                                                    #
#                                                                                         #
#  Loading and analysing Data of all Nodes.                                               #
#                                                                                         #
#                                                                                         #
#  Needed Data Files:                                                                     #
#                                                                                         #
#       raw.json from Hopglass     -> Node Names and Information                          #
#       nodesdb.json from Alfred   -> Region = Segment                                    #
#                                                                                         #
#       regions/<segment>/*.json   -> Polygons of Regions                                 #
#       database/ZipLocations.json -> Dict. of ZIP-Codes with related GPS-Positions       #
#       database/ZipGrid.json      -> Dict. of Grids with ZIP-Codes                       #
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
import socket
import urllib.request
import time
import datetime
import calendar
import json
import re
import hashlib

import dns.resolver
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.update

from glob import glob

from dns.rdataclass import *
from dns.rdatatype import *

from class_ffLocation import *



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------
YANIC_VERSIONS     = ['1.0.0']

MaxInactiveTime    = 10 * 86400     # 10 Days (in Seconds)
MaxOfflineTime     = 30 * 60        # 30 Minutes (in Seconds)
MaxStatusAge       = 15 * 60        # 15 Minutes (in Seconds)

BatmanTimeout      = 10             # 10 Seconds
BatmanMinTQ        =  5             # Minimum Batman TQ for respondd Request

MinNodesCount      = 1000           # Minimum number of Nodes

FreifunkNodeDomain = 'nodes.freifunk-stuttgart.de'

NodeDictName   = 'NodeDict.json'      # Node Database
MacDictName    = 'MacDict.json'       # MAC Translation Dictionary
Region2ZipName = 'Region2ZIP.json'    # Regions with ZIP Codes of Baden-Wuerttemberg
Zip2GpsName    = 'ZipLocations.json'  # GPS location of ZIP-Areas based on OpenStreetMap and OpenGeoDB
ZipGridName    = 'ZipGrid.json'       # Grid of ZIP Codes from Baden-Wuerttemberg


ffsIPv6Template     = re.compile('^fd21:b4dc:4b[0-9]{2}:0?:')

GwMacTemplate       = re.compile('^02:00:(3[1-9])(:[0-9]{2}){3}')
GwIdTemplate        = re.compile('^0200(3[1-9])([0-9]{2}){3}')

MacAdrTemplate      = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
McastMacTemplate    = re.compile('^(00(:00){5})|(ff(:ff){5})|(33:33(:[0-9a-f]{2}){4})|(01:00:5e:[0-7][0-9a-f](:[0-9a-f]{2}){2})')
MonitorMacTemplate  = re.compile('^02:00:3[1-9]:[0-9]{2}:ff:[0-9]{2}')

NodeIdTemplate      = re.compile('^[0-9a-f]{12}$')

PeerTemplate        = re.compile('^ffs-[0-9a-f]{12}')

ZipTemplate         = re.compile('^[0-9]{5}$')
SegmentTemplate     = re.compile('^[0-9]{2}$')

KeyDirTemplate      = re.compile('^vpn[0-9]{2}$')
FastdKeyTemplate    = re.compile('^[0-9a-f]{64}$')
BadNameTemplate     = re.compile('.*[|/\\<>]+.*')

NODETYPE_UNKNOWN       = 0
NODETYPE_LEGACY        = 1
NODETYPE_SEGMENT_LIST  = 2
NODETYPE_DNS_SEGASSIGN = 3
NODETYPE_MTU_1340      = 4

NODESTATE_UNKNOWN      = '?'
NODESTATE_OFFLINE      = '#'
NODESTATE_ONLINE_MESH  = ' '
NODESTATE_ONLINE_VPN   = 'V'

RESPONDD_PORT          = 1001
RESPONDD_TIMEOUT       = 2.0

CPE_TEMP_SEGMENT       = 23



class ffNodeInfo:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,AccountsDict,GitPath,DatabasePath):

        # public Attributes
        self.MAC2NodeIDDict = {}          # Dictionary of all Nodes' MAC-Addresses and related Main Address
        self.ffNodeDict     = {}          # Dictionary of Nodes [MainMAC] with their Name, VPN-Uplink
        self.Alerts         = []          # List of  Alert-Messages
        self.AnalyseOnly    = False       # Locking automatic Actions due to inconsistent Data

        # private Attributes
        self.__AccountsDict = AccountsDict
        self.__GitPath      = GitPath
        self.__DatabasePath = DatabasePath

        # Initializations
        socket.setdefaulttimeout(5)

        self.__LoadNodeDict()             # ffNodeDict[ffNodeMAC] -> saved Infos of ffNodes

        self.__LoadYanicData()            # Load Node Info from Yanic Server
        self.__LoadHopglassData()         # Load Node Info from Hopglass Server
        self.__LoadBatmanData()           # Load Node Info from Batman Translation Table
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



    #-------------------------------------------------------------
    # private function "__GenerateGluonMACs(MainMAC)"
    #
    #   Create Batman MeshMAC-List for Gluon >= 2016.2.x
    #
    # reference = Gluon Source:
    #
    #   /package/gluon-core/luasrc/usr/lib/lua/gluon/util.lua
    #
    # function generate_mac(i)
    # -- 0 + 8: client0; Mesh-on-WAN
    # -- 1 + 9: mesh0 (IEEE 802.11s)
    # -- 2 + a: ibss0
    # -- 3 + b: wan_radio0 (private WLAN); batman-adv primary address
    # -- 4 + c: client1; Mesh-on-LAN
    # -- 5 + d: mesh1 (IEEE 802.11s)
    # -- 6 + e: ibss1
    # -- 7 + f: wan_radio1 (private WLAN); mesh VPN
    #
    #  local hashed = string.sub(hash.md5(sysconfig.primary_mac), 0, 12)
    #  local m1, m2, m3, m4, m5, m6 = string.match(hashed, '(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)')
    #
    #  m1 = tonumber(m1, 16)
    #  m6 = tonumber(m6, 16)
    #
    #  m1 = nixio.bit.bor(m1, 0x02)  -- set locally administered bit
    #  m1 = nixio.bit.band(m1, 0xFE) -- unset the multicast bit
    #
    #  m6 = nixio.bit.band(m6, 0xF8) -- zero the last three bits (space needed for counting)
    #  m6 = m6 + i                   -- add virtual interface id
    #
    # return string.format('%02x:%s:%s:%s:%s:%02x', m1, m2, m3, m4, m5, m6)
    #-------------------------------------------------------------
    def __GenerateGluonMACs(self,MainMAC):

        mHash = hashlib.md5(MainMAC.encode(encoding='UTF-8'))
        vMAC = mHash.hexdigest()

        m1Main = int(vMAC[0:2],16)
        m6Main = int(vMAC[10:12],16)

        m1New    = hex((m1Main | 0x02) & 0xfe)[2:].zfill(2)
        m1to5New = m1New + ':' + vMAC[2:4] + ':' + vMAC[4:6] + ':' + vMAC[6:8] + ':' + vMAC[8:10] + ':'

        GluonMacList = []

        for i in range(8):
            GluonMacList.append(m1to5New + hex((m6Main & 0xf8) + i)[2:].zfill(2))

        return GluonMacList



    #-------------------------------------------------------------
    # private function "__AddGluonMACs(MainMAC,MeshMAC)"
    #
    #   add MeshMACs to MAC2NodeIDDict
    #
    #-------------------------------------------------------------
    def __AddGluonMACs(self,MainMAC,MeshMAC):

        if MeshMAC is None:
            GluonMacList = self.__GenerateGluonMACs(MainMAC)
        else:
            GluonMacList = [ MeshMAC ]

        if MainMAC in self.MAC2NodeIDDict:
            if self.MAC2NodeIDDict[MainMAC] != MainMAC:
                print('!!! MainMAC is MeshMAC of other Node:  %s -> %s = \'%s\'' % (
                    MainMAC,self.MAC2NodeIDDict[MainMAC],self.ffNodeDict[self.MAC2NodeIDDict[MainMAC]]['Name']))

                if self.ffNodeDict[MainMAC]['last_online'] > self.ffNodeDict[self.MAC2NodeIDDict[MainMAC]]['last_online']:
                    print(' >> Other Node is older - this Node is used: %s = \'%s\'\n' % (MainMAC,self.ffNodeDict[MainMAC]['Name']))
                    self.ffNodeDict[self.MAC2NodeIDDict[MainMAC]]['Status'] = NODESTATE_UNKNOWN
                    self.MAC2NodeIDDict[MainMAC] = MainMAC
                else:
                    print(' >> This Node is older - other Node is used: %s = \'%s\'\n' % (
                        self.MAC2NodeIDDict[MainMAC],self.ffNodeDict[self.MAC2NodeIDDict[MainMAC]]['Name']))
                    self.ffNodeDict[MainMAC]['Status'] = NODESTATE_UNKNOWN
                    GluonMacList = []    # don't register this Node
        else:
            self.MAC2NodeIDDict[MainMAC] = MainMAC

        for BatmanMAC in GluonMacList:
            if BatmanMAC in self.MAC2NodeIDDict:
                if self.MAC2NodeIDDict[BatmanMAC] != MainMAC:
                    print('!!! MAC-Collision:  %s -> %s = \'%s\'' % (BatmanMAC,MainMAC,self.ffNodeDict[MainMAC]['Name']))
                    print('    Curr. stored:   %s = \'%s\'' % (self.MAC2NodeIDDict[BatmanMAC],self.ffNodeDict[self.MAC2NodeIDDict[BatmanMAC]]['Name']))

                    if self.ffNodeDict[MainMAC]['last_online'] > self.ffNodeDict[self.MAC2NodeIDDict[BatmanMAC]]['last_online']:
                        BadMAC = self.MAC2NodeIDDict[BatmanMAC]
                        self.MAC2NodeIDDict[BatmanMAC] = MainMAC
                        print('    >> Removing:    %s = \'%s\'\n' % (BadMAC,self.ffNodeDict[BadMAC]['Name']))
                        BadItemsList = []

                        for MAC in self.MAC2NodeIDDict:
                            if self.MAC2NodeIDDict[MAC] == BadMAC:
                                BadItemsList.append(MAC)

                        for MAC in BadItemsList:
                            del self.MAC2NodeIDDict[MAC]
                    else:
                        BadMAC = MainMAC
                        del self.MAC2NodeIDDict[BadMAC]
                        print('    Bad Node:       %s = \'%s\'\n' % (BadMAC,self.ffNodeDict[BadMAC]['Name']))

                    self.ffNodeDict[BadMAC]['last_online'] = 0
                    self.ffNodeDict[BadMAC]['Status'] = NODESTATE_UNKNOWN

                    if BadMAC == MainMAC:  break

            else:
                self.MAC2NodeIDDict[BatmanMAC] = MainMAC

            if BatmanMAC not in self.ffNodeDict[MainMAC]['MeshMACs']:
                self.ffNodeDict[MainMAC]['MeshMACs'].append(BatmanMAC)

        return



    #-------------------------------------------------------------
    # private function "__LoadNodeDict"
    #
    #   Load ffNodeDict
    #-------------------------------------------------------------
    def __LoadNodeDict(self):

        print('Loading',NodeDictName,'...')
        CurrentTime = int(time.time())
        NodeCount = 0

        try:
            JsonFile = open(os.path.join(self.__DatabasePath,NodeDictName), mode='r')
            jsonNodeDict = json.load(JsonFile)
            JsonFile.close()

        except:
            print('\n!! Error on Reading %s !!\n' % (NodeDictName))

        else:
            for ffNodeMAC in jsonNodeDict:
                if (CurrentTime - jsonNodeDict[ffNodeMAC]['last_online']) <= MaxInactiveTime:

                    self.ffNodeDict[ffNodeMAC] = {
                        'Name': jsonNodeDict[ffNodeMAC]['Name'],
                        'Hardware': jsonNodeDict[ffNodeMAC]['Hardware'],
                        'Status': jsonNodeDict[ffNodeMAC]['Status'],
                        'last_online': jsonNodeDict[ffNodeMAC]['last_online'],
                        'Uptime': 0.0,
                        'Clients': 0,
                        'Latitude': jsonNodeDict[ffNodeMAC]['Latitude'],
                        'Longitude': jsonNodeDict[ffNodeMAC]['Longitude'],
                        'ZIP': jsonNodeDict[ffNodeMAC]['ZIP'],
                        'Region': '??',
                        'DestSeg': None,
                        'Firmware': '?.?+????-??-??',
                        'GluonType': jsonNodeDict[ffNodeMAC]['GluonType'],
                        'MeshMACs': jsonNodeDict[ffNodeMAC]['MeshMACs'],
                        'IPv6': jsonNodeDict[ffNodeMAC]['IPv6'],
                        'Segment': jsonNodeDict[ffNodeMAC]['Segment'],
                        'SegMode': 'auto',
                        'KeyDir': '',
                        'KeyFile': '',
                        'FastdKey': '',
                        'FastdGW': None,
                        'InCloud': None,
                        'Neighbours': [],
                        'AutoUpdate': None,
                        'Owner': jsonNodeDict[ffNodeMAC]['Owner'],
                        'Source': 'DB'
                    }

                    NodeCount += 1

                    if jsonNodeDict[ffNodeMAC]['MeshMACs'] == []:
                        self.__AddGluonMACs(ffNodeMAC,None)
                    else:
                        for MeshMAC in jsonNodeDict[ffNodeMAC]['MeshMACs']:
                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                    if (CurrentTime - jsonNodeDict[ffNodeMAC]['last_online']) > MaxOfflineTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_OFFLINE
                    else:
                        self.ffNodeDict[ffNodeMAC]['Neighbours'] = jsonNodeDict[ffNodeMAC]['Neighbours']

                    if 'AutoUpdate' in jsonNodeDict[ffNodeMAC]:
                        self.ffNodeDict[ffNodeMAC]['AutoUpdate'] = jsonNodeDict[ffNodeMAC]['AutoUpdate']

        print('... %d Nodes done.\n' % (NodeCount))
        return NodeCount



    #=========================================================================
    # public function "WriteNodeDict"
    #
    #
    #=========================================================================
    def WriteNodeDict(self):

        print('Writing',NodeDictName,'...')
        JsonFile = open(os.path.join(self.__DatabasePath,NodeDictName), mode='w+')
        json.dump(self.ffNodeDict,JsonFile)
        JsonFile.close()

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__IsOnline"
    #
    #   True = Node is Online
    #-----------------------------------------------------------------------
    def __IsOnline(self,ffNodeMAC):

        if ffNodeMAC in self.ffNodeDict:
            OnlineState = self.ffNodeDict[ffNodeMAC]['Status'] in [ NODESTATE_ONLINE_MESH, NODESTATE_ONLINE_VPN ]
        else:
            OnlineState = False

        return OnlineState



    #-------------------------------------------------------------
    # private function "__SetSegmentAwareness(FirmwareRelease)"
    #
    #   check segment awareness of gluon
    #     0 = unknown
    #     1 = old FW without segmentation
    #     2 = fix segments 1 .. 8
    #     3 = new segment assignment by DNS
    #-------------------------------------------------------------
    def __SetSegmentAwareness(self,FirmwareRelease):

        GluonType = NODETYPE_UNKNOWN

        if FirmwareRelease is not None:
            if FirmwareRelease[:14] >= '1.3+2017-09-13':
                GluonType = NODETYPE_MTU_1340
            elif FirmwareRelease[:14] >= '1.0+2017-02-14':
                GluonType = NODETYPE_DNS_SEGASSIGN
            elif FirmwareRelease[:14] >= '0.7+2016.01.02':
                GluonType = NODETYPE_SEGMENT_LIST
            else:
                GluonType = NODETYPE_LEGACY

        return GluonType



    #-----------------------------------------------------------------------
    # private function "__ProcessResponddData"
    #
    #   Analyse and load Data from Node via respondd
    #
    # self.ffNodeDict[ffNodeMAC] -> all Infos of ffNode
    # self.MAC2NodeIDDict[ffNode] -> Main MAC
    #
    #     return:    True = Data can be used
    #-----------------------------------------------------------------------
    def __ProcessResponddData(self,NodeDict,CurrentTime,DateFormat):

        if (('lastseen' not in NodeDict) or
            ('nodeinfo' not in NodeDict) or
            ('statistics' not in NodeDict) or
            ('neighbours' not in NodeDict)):

            if DateFormat is None:
                print('+++ Invalid Record!',NodeDict)
            return False

        if ((NodeDict['nodeinfo'] is None or 'node_id' not in NodeDict['nodeinfo']) or
            (NodeDict['statistics'] is None or 'node_id' not in NodeDict['statistics'])):
            print('    +++ Missing node_id!',NodeDict)
            return False

        ffNodeID = NodeDict['nodeinfo']['node_id'].strip().lower()

        if DateFormat is None:
            LastSeen = NodeDict['lastseen']
        else:
            LastSeen = int(calendar.timegm(time.strptime(NodeDict['lastseen'], DateFormat)))

        if (CurrentTime - LastSeen) > MaxInactiveTime:
            if DateFormat is None:
                print('+++ Data too old: ffs-%s = %d Min' % (ffNodeID,(CurrentTime - LastSeen) / 60))
            return False    # Data is obsolete / too old


        if NodeDict['statistics']['node_id'] != NodeDict['nodeinfo']['node_id']:
            print('++ NodeID-Mismatch: nodeinfo = %s / statistics = %s\n' %
                     (NodeDict['nodeinfo']['node_id'],NodeDict['statistics']['node_id']))
            return False

        if NodeDict['neighbours'] is not None:
            if 'node_id' not in NodeDict['neighbours']:
                print('+++ Missing node_id of neighbours!',NodeDict['neighbours'])
                return False
            elif NodeDict['neighbours']['node_id'] != NodeDict['nodeinfo']['node_id']:
                print('++ NodeID-Mismatch: nodeinfo = %s / neighbours = %s\n' % (NodeDict['nodeinfo']['node_id'],NodeDict['neighbours']['node_id']))
                return False

        if (('software' not in NodeDict['nodeinfo']) or
            ('hostname' not in NodeDict['nodeinfo']) or
            ('network' not in NodeDict['nodeinfo'])):
            print('+++ NodeInfo broken!',NodeDict['nodeinfo'])
            return False

        if GwIdTemplate.match(ffNodeID):
            print(' ++ Gateway Data found: %s' % (ffNodeID))
            return False

        if (('firmware' not in NodeDict['nodeinfo']['software']) or
            ('release' not in NodeDict['nodeinfo']['software']['firmware']) or
            (NodeDict['nodeinfo']['software']['firmware']['release'] is None) or
            ('mac' not in NodeDict['nodeinfo']['network'])):
            print(' ++ Broken Data in nodeinfo Record %s !' % (ffNodeID))
            print(NodeDict)
            return False


        ffNodeMAC = NodeDict['nodeinfo']['network']['mac'].strip().lower()

        if not MacAdrTemplate.match(ffNodeMAC):
            print('!! Invalid MAC Format: %s -> %s' % (ffNodeID,ffNodeMAC))
            return False

        if GwMacTemplate.match(ffNodeMAC):  return False    # Data is from Gateway

        if ffNodeID != ffNodeMAC.replace(':',''):
            print('++ NodeID / MAC Mismatch: NodeID = %s / MAC = %s' % (ffNodeID,ffNodeMAC))
            return False


        #---------- Processing Data of active Node ----------
        if ffNodeMAC not in self.ffNodeDict:
            if len(self.ffNodeDict) > MinNodesCount:
                print('++ New Node: %s = \'%s\'' % (ffNodeMAC,NodeDict['nodeinfo']['hostname']))

            self.ffNodeDict[ffNodeMAC] = {
                'Name': None,
                'Hardware': '- unknown -',
                'Status': NODESTATE_UNKNOWN,
                'last_online': 0,
                'Uptime': 0.0,
                'Clients': 0,
                'Latitude': None,
                'Longitude': None,
                'ZIP': None,
                'Region': '??',
                'DestSeg': None,
                'Firmware': '?.?+????-??-??',
                'GluonType': NODETYPE_UNKNOWN,
                'MeshMACs':[],
                'IPv6': None,
                'Segment': None,
                'SegMode': 'auto',
                'KeyDir': '',
                'KeyFile': '',
                'FastdGW': None,
                'FastdKey': '',
                'InCloud': None,
                'Neighbours': [],
                'AutoUpdate': None,
                'Owner': None,
                'Source': None
            }

#        if LastSeen < self.ffNodeDict[ffNodeMAC]['last_online']:
        if LastSeen < self.ffNodeDict[ffNodeMAC]['last_online'] and self.ffNodeDict[ffNodeMAC]['Source'] != 'DB':
            return False    # Newer Node-Info already existing ...


        #---------- Current Data of Node will be used ----------
        self.ffNodeDict[ffNodeMAC]['Name']        = NodeDict['nodeinfo']['hostname']
        self.ffNodeDict[ffNodeMAC]['last_online'] = LastSeen
        self.ffNodeDict[ffNodeMAC]['Status']      = NODESTATE_OFFLINE
        self.ffNodeDict[ffNodeMAC]['MeshMACs']    = []
        self.ffNodeDict[ffNodeMAC]['Clients']     = 0
        self.ffNodeDict[ffNodeMAC]['Latitude']    = None
        self.ffNodeDict[ffNodeMAC]['Longitude']   = None
        self.ffNodeDict[ffNodeMAC]['ZIP']         = None

        if 'clients' in NodeDict['statistics']:
            if NodeDict['statistics']['clients'] is not None:
                if 'total' in NodeDict['statistics']['clients']:
                    self.ffNodeDict[ffNodeMAC]['Clients'] = int(NodeDict['statistics']['clients']['total'])
                else:
                    print('!!! total statistics missing: %s' % (NodeIdx))

        if 'hardware' in NodeDict['nodeinfo']:
            if 'model' in NodeDict['nodeinfo']['hardware']:
                self.ffNodeDict[ffNodeMAC]['Hardware'] = NodeDict['nodeinfo']['hardware']['model']

        if 'location' in NodeDict['nodeinfo']:
            if 'latitude' in NodeDict['nodeinfo']['location'] and 'longitude' in NodeDict['nodeinfo']['location']:
                self.ffNodeDict[ffNodeMAC]['Latitude']  = NodeDict['nodeinfo']['location']['latitude']
                self.ffNodeDict[ffNodeMAC]['Longitude'] = NodeDict['nodeinfo']['location']['longitude']

            if 'zip' in NodeDict['nodeinfo']['location']:
                self.ffNodeDict[ffNodeMAC]['ZIP'] = str(NodeDict['nodeinfo']['location']['zip']).strip()

        if 'custom_fields' in NodeDict:
            if 'zip' in NodeDict['custom_fields']:
                self.ffNodeDict[ffNodeMAC]['ZIP'] = str(NodeDict['custom_fields']['zip']).strip()

        if 'owner' in NodeDict['nodeinfo']:
            if NodeDict['nodeinfo']['owner'] is not None:
                if 'contact' in NodeDict['nodeinfo']['owner']:
                    self.ffNodeDict[ffNodeMAC]['Owner'] = NodeDict['nodeinfo']['owner']['contact']

        if 'mesh' in NodeDict['nodeinfo']['network']:
            for InterfaceType in NodeDict['nodeinfo']['network']['mesh']['bat0']['interfaces']:
                for MeshMAC in NodeDict['nodeinfo']['network']['mesh']['bat0']['interfaces'][InterfaceType]:
                    self.__AddGluonMACs(ffNodeMAC,MeshMAC)

        elif 'mesh_interfaces' in NodeDict['nodeinfo']['network']:
            for MeshMAC in NodeDict['nodeinfo']['network']['mesh_interfaces']:
                self.__AddGluonMACs(ffNodeMAC,MeshMAC)

        if 'autoupdater' in NodeDict['nodeinfo']['software']:
            if 'branch' in NodeDict['nodeinfo']['software']['autoupdater'] and 'enabled' in NodeDict['nodeinfo']['software']['autoupdater']:
                self.ffNodeDict[ffNodeMAC]['AutoUpdate'] = NodeDict['nodeinfo']['software']['autoupdater']['branch']
            else:
                self.ffNodeDict[ffNodeMAC]['AutoUpdate'] = '---'

        if (CurrentTime - LastSeen) <= MaxOfflineTime:
            self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH

            if 'addresses' in NodeDict['nodeinfo']['network']:
                for NodeAddress in NodeDict['nodeinfo']['network']['addresses']:
                    if ffsIPv6Template.match(NodeAddress):
                        self.ffNodeDict[ffNodeMAC]['IPv6'] = NodeAddress

            if 'gateway' in NodeDict['statistics']:
                if GwMacTemplate.match(NodeDict['statistics']['gateway']):
                    self.ffNodeDict[ffNodeMAC]['Segment'] = int(NodeDict['statistics']['gateway'][9:11])

            if 'gateway_nexthop' in NodeDict['statistics']:
                if GwMacTemplate.match(NodeDict['statistics']['gateway_nexthop']):
                    self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN

            if 'mesh_vpn' in NodeDict['statistics']:
                if 'groups' in NodeDict['statistics']['mesh_vpn']:
                    if 'backbone' in NodeDict['statistics']['mesh_vpn']['groups']:
                        if 'peers' in NodeDict['statistics']['mesh_vpn']['groups']['backbone']:
                            GWpeers = NodeDict['statistics']['mesh_vpn']['groups']['backbone']['peers']

                            for Uplink in GWpeers:
                                if GWpeers[Uplink] is not None:
                                    if 'established' in GWpeers[Uplink]:
                                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN

            if NodeDict['neighbours'] is not None:
                if 'batadv' in NodeDict['neighbours']:
                    self.ffNodeDict[ffNodeMAC]['Neighbours'] = []

                    for MeshMAC in NodeDict['neighbours']['batadv']:
                        if 'neighbours' in NodeDict['neighbours']['batadv'][MeshMAC]:
                            for ffNeighbour in NodeDict['neighbours']['batadv'][MeshMAC]['neighbours']:
                                if MacAdrTemplate.match(ffNeighbour):
                                    if GwMacTemplate.match(ffNeighbour):
                                        if self.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_ONLINE_VPN:
                                            print('++ Node has GW %s as Neighbour but no VPN: %s = \"%s\"' % (ffNeighbour,ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                                            self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                                    elif ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours']:
                                        self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

            if 'uptime' in NodeDict['statistics']:
                self.ffNodeDict[ffNodeMAC]['Uptime'] = NodeDict['statistics']['uptime']

        if self.ffNodeDict[ffNodeMAC]['MeshMACs'] == []:
            self.__AddGluonMACs(ffNodeMAC,None)

        self.ffNodeDict[ffNodeMAC]['Firmware']  = NodeDict['nodeinfo']['software']['firmware']['release']
        self.ffNodeDict[ffNodeMAC]['GluonType'] = self.__SetSegmentAwareness(self.ffNodeDict[ffNodeMAC]['Firmware'])

        return True



    #-----------------------------------------------------------------------
    # private function "__LoadYanicData"
    #
    #   Load and analyse raw.json from Yanic Server
    #
    # RawJsonDict <- raw.json
    #
    # self.ffNodeDict[ffNodeMAC] -> all Infos of ffNode
    # self.MAC2NodeIDDict[ffNode] -> Main MAC
    #-----------------------------------------------------------------------
    def __LoadYanicData(self):

        print('Loading raw.json from Yanic Server ...')

        if 'YanicData' not in self.__AccountsDict:
            self.__alert('++ Missing Account Data to access Yanic raw.json !!!\n')
            self.AnalyseOnly = True
            return

        CurrentTime = int(time.time())
        InfoTime = 0
        NewestTime = 0
        AllNodesCount = 0
        UsedNodesCount = 0
        OnlineNodesCount = 0

        YanicAccessDict = self.__AccountsDict['YanicData']
        RawJsonDict = None
        Retries = 5


        while RawJsonDict is None and Retries > 0:
            Retries -= 1

            try:
                passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                passman.add_password(None, YanicAccessDict['URL'], YanicAccessDict['Username'], YanicAccessDict['Password'])
                authhandler = urllib.request.HTTPBasicAuthHandler(passman)
                opener = urllib.request.build_opener(authhandler)
                urllib.request.install_opener(opener)

                RawJsonHTTP = urllib.request.urlopen(YanicAccessDict['URL'],timeout=15)
                print('... is open ...')
                RawJsonDict = json.loads(RawJsonHTTP.read().decode('utf-8'))
                RawJsonHTTP.close()
                InfoTime = int(calendar.timegm(time.strptime(RawJsonDict['updated_at'], '%Y-%m-%dT%H:%M:%S%z')))
            except:
                print('** need retry ...')
                RawJsonDict = None
                time.sleep(2)

        if RawJsonDict is None:
            self.__alert('++ Error on loading raw.json from Yanic!!!\n')
            return

        if 'version' not in RawJsonDict or 'nodes' not in RawJsonDict:
            self.__alert('++ Bad Format of Yanic raw.json!')
            return

        if RawJsonDict['version'] not in YANIC_VERSIONS:
            self.__alert('++ Bad Version of Yanic raw.json: %s (expecting %s)!' % (RawJsonDict['version'],YANIC_VERSION))
            return

        if 'updated_at' in RawJsonDict:
            InfoTime = int(calendar.timegm(time.strptime( RawJsonDict['updated_at'],'%Y-%m-%dT%H:%M:%S%z') ))

        if (CurrentTime - InfoTime) > MaxStatusAge:
            self.__alert('++ Yanic raw.json is too old: %d Sec.!' % (CurrentTime - InfoTime))
            return


        print('Analysing raw.json (%d Records, Yanic Data Age = %d Sec.) ...' % (len(RawJsonDict['nodes']),CurrentTime - InfoTime))

        for NodeDict in RawJsonDict['nodes']:
            if self.__ProcessResponddData(NodeDict,CurrentTime,'%Y-%m-%dT%H:%M:%S%z'):
                UsedNodesCount += 1
                ffNodeMAC = NodeDict['nodeinfo']['network']['mac'].strip().lower()
                self.ffNodeDict[ffNodeMAC]['Source'] = 'Yanic'

                if self.ffNodeDict[ffNodeMAC]['last_online'] > NewestTime:
                    NewestTime = self.ffNodeDict[ffNodeMAC]['last_online']

                if self.__IsOnline(ffNodeMAC):
                    OnlineNodesCount += 1

        print('... %d Nodes selected, online = %d (Age = %d sec.)\n' % (UsedNodesCount,OnlineNodesCount,CurrentTime-NewestTime))

        if UsedNodesCount > MinNodesCount and (CurrentTime - NewestTime) < MaxStatusAge:
            self.AnalyseOnly = False

        return



    #-----------------------------------------------------------------------
    # private function "__LoadHopglassData"
    #
    #   Load and analyse raw.json from Hopglass Server
    #
    # RawJsonDict <- raw.json
    #
    # self.ffNodeDict[ffNodeMAC] -> all Infos of ffNode
    # self.MAC2NodeIDDict[ffNode] -> Main MAC
    #-----------------------------------------------------------------------
    def __LoadHopglassData(self):

        print('Loading raw.json from Hopglass Server ...')

        if 'HopglassData' not in self.__AccountsDict:
            self.__alert('++ Missing Account Data to access Hopglass raw.json !!!\n')
            self.AnalyseOnly = True
            return

        CurrentTime = int(time.time())
        NewestTime = 0
        AllNodesCount = 0
        UsedNodesCount = 0
        OnlineNodesCount = 0

        HGAccessDict = self.__AccountsDict['HopglassData']
        RawJsonDict = None
        Retries = 5


        while RawJsonDict is None and Retries > 0:
            Retries -= 1

            try:
                passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                passman.add_password(None, HGAccessDict['URL'], HGAccessDict['Username'], HGAccessDict['Password'])
                authhandler = urllib.request.HTTPBasicAuthHandler(passman)
                opener = urllib.request.build_opener(authhandler)
                urllib.request.install_opener(opener)

                RawJsonHTTP = urllib.request.urlopen(HGAccessDict['URL'],timeout=15)
                print('... is open ...')
                RawJsonDict = json.loads(RawJsonHTTP.read().decode('utf-8'))
                RawJsonHTTP.close()
            except:
                print('** need retry ...')
                RawJsonDict = None
                time.sleep(2)

        if RawJsonDict is None:
            if len(self.ffNodeDict) < MinNodesCount:
                self.AnalyseOnly = True

            self.__alert('++ Error on loading raw.json from Hopglass!!!\n')
            return


        print('Analysing raw.json (%d Records) ...' % (len(RawJsonDict)))

        for NodeIdx in RawJsonDict:
            if self.__ProcessResponddData(RawJsonDict[NodeIdx],CurrentTime,'%Y-%m-%dT%H:%M:%S.%fZ'):
                UsedNodesCount += 1
                ffNodeMAC = RawJsonDict[NodeIdx]['nodeinfo']['network']['mac'].strip().lower()
                self.ffNodeDict[ffNodeMAC]['Source'] = 'Hopglass'

                if self.ffNodeDict[ffNodeMAC]['last_online'] > NewestTime:
                    NewestTime = self.ffNodeDict[ffNodeMAC]['last_online']

                if self.__IsOnline(ffNodeMAC):
                    OnlineNodesCount += 1

        print('... %d Nodes selected, online = %d (Age = %d sec.)\n' % (UsedNodesCount,OnlineNodesCount,CurrentTime-NewestTime))

        if UsedNodesCount > MinNodesCount and (CurrentTime - NewestTime) < MaxStatusAge:
            self.AnalyseOnly = False

        return



    #-----------------------------------------------------------------------
    # private function "__InfoFromRespondd"
    #
    #  -> NodeJsonDict
    #-----------------------------------------------------------------------
    def __InfoFromRespondd(self,NodeMAC,NodeIF,Request):

        NodeIPv6 = 'fe80::' + hex(int(NodeMAC[0:2],16) ^ 0x02)[2:]+NodeMAC[3:8]+'ff:fe'+NodeMAC[9:14]+NodeMAC[15:17] + '%'+NodeIF

        print('    >> Requesting %s via respondd from %s ...' % (Request,NodeIPv6))
        Retries = 3
        NodeJsonDict = None

        while NodeJsonDict is None and Retries > 0:
            Retries -= 1

            try:
                AddrInfo = socket.getaddrinfo(NodeIPv6, RESPONDD_PORT, socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP, socket.AI_NUMERICHOST)[0]

                DestAddrObj = AddrInfo[4]

                ResponddSock = socket.socket(AddrInfo[0], AddrInfo[1], AddrInfo[2])
                ResponddSock.settimeout(RESPONDD_TIMEOUT)
                ResponddSock.bind(('::', RESPONDD_PORT, 0, DestAddrObj[3]))

                ResponddSock.sendto(Request.encode("UTF-8"), DestAddrObj)
                NodeJsonDict = json.loads(ResponddSock.recv(4096).decode('UTF-8'))
                ResponddSock.close()
            except:
                NodeJsonDict = None
                time.sleep(2)

        if NodeJsonDict is None:
            print('    +++ Error on respondd!')

        return NodeJsonDict



    #-----------------------------------------------------------------------
    # private function "__GetBatmanInterfaces"
    #
    #  -> Interface-List
    #-----------------------------------------------------------------------
    def __GetBatmanInterfaces(self):

        InterfaceList = socket.if_nameindex()
        BatmanList = []

        for IF_Tuple in InterfaceList:
            if IF_Tuple[1][:3] == 'bat':
                BatmanList.append(IF_Tuple[1])

        return BatmanList



    #=======================================================================
    # private init function "__LoadBatmanData"
    #
    #   Find Nodes by analyzing batman global Translation Table (TG)
    #
    #-----------------------------------------------------------------------
    def __LoadBatmanData(self):

        print('\nAnalyzing Batman Tables ...')
        CurrentTime = int(time.time())
        TotalNodes = 0
        TotalClients = 0

        BatmanInterfaceList = self.__GetBatmanInterfaces()

        for BatIF in sorted(BatmanInterfaceList):
            ffSeg = int(BatIF[3:])
            print('... Segment %02d ...' % (ffSeg))

            BatctlCmd = ('/usr/sbin/batctl -m %s tg' % (BatIF)).split()    # batman translation table ...

            try:
                BatctlTg = subprocess.run(BatctlCmd, stdout=subprocess.PIPE, timeout=BatmanTimeout)
                BatctlResult = BatctlTg.stdout.decode('utf-8')
            except:
                print('++ ERROR accessing batman: %s' % (BatctlCmd))
                BatmanTransTable = None
            else:
                NodeList = []
                ClientList = []

                for BatctlLine in BatctlResult.split('\n'):
                    BatctlInfo = BatctlLine.replace('(','').replace(')','').split()

                    if len(BatctlInfo) > 6:
                        if BatctlInfo[0] == '*' and BatctlInfo[3][0] == '[':

                            ffNodeMAC = BatctlInfo[1]
                            ffMeshMAC = BatctlInfo[5]
                            ffTQ      = int(BatctlInfo[6])

                            if (MacAdrTemplate.match(ffNodeMAC) and not McastMacTemplate.match(ffNodeMAC) and not GwMacTemplate.match(ffNodeMAC) and
                                MacAdrTemplate.match(ffMeshMAC) and not McastMacTemplate.match(ffMeshMAC) and not GwMacTemplate.match(ffMeshMAC)):

                                BatmanMacList = self.__GenerateGluonMACs(ffNodeMAC)

                                if ((ffNodeMAC in self.ffNodeDict) and ((CurrentTime - self.ffNodeDict[ffNodeMAC]['last_online']) < MaxStatusAge) and
                                    (self.ffNodeDict[ffNodeMAC]['Source'] != 'DB')):
                                    #---------- Current data of Node already available ----------

                                    if ffNodeMAC not in NodeList:
                                        NodeList.append(ffNodeMAC)
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = ffSeg
                                        self.__AddGluonMACs(ffNodeMAC,ffMeshMAC)

                                        if self.ffNodeDict[ffNodeMAC]['Source'] != 'respondd':
                                            if not self.__IsOnline(ffNodeMAC):
                                                self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH
                                                print('    >> Node is online: %s = %s\n' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                                        if ffMeshMAC not in BatmanMacList:  # Data of known Node with non-Gluon MAC
                                            print('    !! Special Node in Batman TG: %s -> %s = %s' % (ffMeshMAC,ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                                elif ffMeshMAC in BatmanMacList:
                                    #---------- Node without current data available ----------

                                    if ffNodeMAC not in NodeList and ffTQ >= BatmanMinTQ:
                                        print('    ++ New Node in Batman TG: NodeID = %s (TQ = %d) -> Mesh = %s' % (ffNodeMAC,ffTQ,ffMeshMAC))
                                        NodeList.append(ffNodeMAC)
                                        NodeName = None
                                        ResponddDict = { 'lastseen':CurrentTime, 'nodeinfo':None, 'statistics':None, 'neighbours':None }

                                        ResponddDict['nodeinfo'] = self.__InfoFromRespondd(ffNodeMAC, 'bat%02d' % (ffSeg),'nodeinfo')

                                        if ResponddDict['nodeinfo'] is not None:
                                            if 'hostname' in ResponddDict['nodeinfo']:
                                                NodeName = ResponddDict['nodeinfo']['hostname']

                                                if NodeName is None:
                                                    if ffNodeMAC in self.ffNodeDict:
                                                        NodeName = self.ffNodeDict[ffNodeMAC]['Name']
                                                    else:
                                                        NodeName = '- ?? -'

                                            ResponddDict['statistics'] = self.__InfoFromRespondd(ffNodeMAC, 'bat%02d' % (ffSeg),'statistics')

                                            if ResponddDict['statistics'] is not None:
                                                ResponddDict['neighbours'] = self.__InfoFromRespondd(ffNodeMAC, 'bat%02d' % (ffSeg),'neighbours')

                                        if self.__ProcessResponddData(ResponddDict,CurrentTime,None):
                                            self.ffNodeDict[ffNodeMAC]['Source'] = 'respondd'
                                            print('    ** New Node added: %s -> %s = %s\n' % (ffMeshMAC,ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                                        else:
                                            print('       ... Node ignored: %s -> %s = %s\n' % (ffMeshMAC,ffNodeMAC,NodeName))

                                    if ffNodeMAC in self.ffNodeDict:
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = ffSeg
                                        self.__AddGluonMACs(ffNodeMAC,ffMeshMAC)

                                        if not self.__IsOnline(ffNodeMAC):
                                            self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH
                                            print('    >> Node is online: %s = %s' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                                elif ffNodeMAC in self.MAC2NodeIDDict:
                                    #---------- Check for Mesh-MAC in Client-Net ----------

                                    RealNodeMAC = self.MAC2NodeIDDict[ffNodeMAC]

                                    if RealNodeMAC != ffNodeMAC:  # actually ffNodeMAC is a Mesh-MAC of a Node ...
                                        if ffMeshMAC in self.MAC2NodeIDDict:
                                            BaseNodeMAC = self.MAC2NodeIDDict[ffMeshMAC]

                                            if BaseNodeMAC in self.ffNodeDict and RealNodeMAC in self.ffNodeDict:
                                                print('    !! Mesh-MAC in Client Net: %s = \'%s\' -> %s -> %s =\'%s\'' %
                                                         (BaseNodeMAC,self.ffNodeDict[BaseNodeMAC]['Name'],ffNodeMAC,RealNodeMAC,self.ffNodeDict[RealNodeMAC]['Name']))

                                                self.ffNodeDict[BaseNodeMAC]['Segment'] = ffSeg
                                                self.ffNodeDict[RealNodeMAC]['Segment'] = ffSeg

                                                if not self.__IsOnline(BaseNodeMAC):
                                                    self.ffNodeDict[BaseNodeMAC]['Status'] = NODESTATE_ONLINE_MESH

                                                if not self.__IsOnline(RealNodeMAC):
                                                    self.ffNodeDict[RealNodeMAC]['Status'] = NODESTATE_ONLINE_MESH

                                            else:
                                                print('   !!! ERROR in Database: %s / %s -> %s / %s\n' % (ffNodeMAC,ffMeshMAC,RealNodeMAC,BaseNodeMAC))

                                        else:
                                            print('   !!! Unknown Mesh-MAC in Batman-TG: %s -> %s / %s\n' % (ffMeshMAC,ffNodeMAC,RealNodeMAC))

                                else:  # Data of Client
                                    if ffNodeMAC not in ClientList:
                                        ClientList.append(ffNodeMAC)

                NodeCount = len(NodeList)
                ClientCount = len(ClientList)
                print('      Nodes = %d / Clients = %d' % (NodeCount,ClientCount))

                TotalNodes   += NodeCount
                TotalClients += ClientCount

        print('\nTotalNodes = %d / TotalClients = %d\n... done.\n' %(TotalNodes,TotalClients))
        return



    #=========================================================================
    # public function "AddUplinkInfo"
    #
    #   Add fastd-Infos for Nodes
    #     FastdKeyDict[KeyFileName] = { 'KeyDir','SegMode','PeerMAC','PeerName','PeerKey','VpnMAC','Timestamp','DnsSeg' }
    #
    #=========================================================================
    def AddUplinkInfos(self,FastdKeyDict):

        print('Merging fastd-Infos to Nodes ...')
        addedInfos = 0
        fastdNodes = 0

        for KeyFileName in FastdKeyDict:
            FastdKeyInfo = FastdKeyDict[KeyFileName]
            ffNodeMAC = FastdKeyInfo['PeerMAC']  # is from Key-File, *not* live data!
            ffVpnMAC = FastdKeyInfo['VpnMAC']    # MAC of fastd-Interface with Mesh-Traffic

            if ffVpnMAC is not None:  # Node has VPN-Connection to Gateway
                if MonitorMacTemplate.match(ffVpnMAC):
                    ffVpnMAC = None
                    ffNodeMAC = None
                elif ffVpnMAC in self.MAC2NodeIDDict:
                    if ffNodeMAC != self.MAC2NodeIDDict[ffVpnMAC]:
                        print('++ Node Info Mismatch: %s - %s / %s -> %s = \'%s\'' %
                             (FastdKeyInfo['KeyDir'],ffNodeMAC,ffVpnMAC,self.MAC2NodeIDDict[ffVpnMAC],self.ffNodeDict[self.MAC2NodeIDDict[ffVpnMAC]]['Name']))
                        ffNodeMAC = self.MAC2NodeIDDict[ffVpnMAC]
                else:
                    GluonMacList = self.__GenerateGluonMACs(ffNodeMAC)

                    if ffVpnMAC in GluonMacList:
                        print('++ Unknown VPN-MAC (Gluon): %s / %s -> %s / %s = \'%s\' -> %s' %
                              (ffVpnMAC,ffNodeMAC,FastdKeyInfo['KeyDir'],KeyFileName,FastdKeyInfo['PeerName'],FastdKeyInfo['VpnGW']))
                    else:
                        print('++ Unknown VPN-MAC (Non-Gluon): %s / %s -> %s / %s = \'%s\' -> %s' %
                              (ffVpnMAC,ffNodeMAC,FastdKeyInfo['KeyDir'],KeyFileName,FastdKeyInfo['PeerName'],FastdKeyInfo['VpnGW']))

            if ffNodeMAC in self.ffNodeDict:
                self.ffNodeDict[ffNodeMAC]['SegMode']  = FastdKeyInfo['SegMode']
                self.ffNodeDict[ffNodeMAC]['KeyDir']   = FastdKeyInfo['KeyDir']
                self.ffNodeDict[ffNodeMAC]['KeyFile']  = KeyFileName
                self.ffNodeDict[ffNodeMAC]['FastdKey'] = FastdKeyInfo['PeerKey']
                addedInfos += 1

                if self.ffNodeDict[ffNodeMAC]['Name'].strip().lower() != FastdKeyInfo['PeerName'].strip().lower():
                    print('++ Hostname Mismatch:  %s = \'%s\' <- \'%s\'' % (KeyFileName,self.ffNodeDict[ffNodeMAC]['Name'],FastdKeyInfo['PeerName']))
                    FastdKeyInfo['PeerName'] = self.ffNodeDict[ffNodeMAC]['Name']

                if ffVpnMAC is not None:   # Node has VPN-Connection to Gateway ...
                    fastdNodes += 1
                    self.__AddGluonMACs(ffNodeMAC,ffVpnMAC)
                    self.ffNodeDict[ffNodeMAC]['FastdGW'] = FastdKeyInfo['VpnGW']

        print('... %d Keys added (%d VPN connections).\n' % (addedInfos,fastdNodes))
        return



    #==============================================================================
    # public function "DumpMacTable"
    #
    #   Dump out MAC-Table
    #==============================================================================
    def DumpMacTable(self,FileName):

        print('Write MAC-Table ...')
        JsonFile = open(os.path.join(self.__DatabasePath,MacDictName), mode='w+')
        json.dump(self.MAC2NodeIDDict,JsonFile)
        JsonFile.close()

        print('Dump MAC-Table ...')
        MacTableFile = open(FileName, mode='w')
        MacTableFile.write('--------------------------------------------\n')
        MacTableFile.write('%-20s -> %-20s\n' % ('FF-MAC', 'Main-MAC'))
        MacTableFile.write('--------------------------------------------\n')

        for ffNodeMAC in sorted(self.MAC2NodeIDDict):
            MacTableFile.write('%-20s -> %-20s\n' % (ffNodeMAC, self.MAC2NodeIDDict[ffNodeMAC]))

        MacTableFile.close()
        print('... done.\n')
        return



    #==============================================================================
    # public function "SetDesiredSegments"
    #
    #   Get Segment from Location (GPS Data or ZIP-Code)
    #==============================================================================
    def SetDesiredSegments(self,LocationInfo):

        print('Setting up Desired Segments from GPS Data or ZIP-Code ...\n')

        if not LocationInfo.LocationDataOK():
            self.__alert('!! No Region Data available !!!')
            self.AnalyseOnly = True
            return False


        for ffNodeMAC in self.ffNodeDict:
            if self.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN:

                GpsRegion  = None
                GpsSegment = None
                GpsZipCode = None

                ZipRegion  = None
                ZipSegment = None

                if self.ffNodeDict[ffNodeMAC]['Longitude'] is not None and self.ffNodeDict[ffNodeMAC]['Latitude'] is not None:
                    (GpsZipCode,GpsRegion,GpsSegment) = LocationInfo.GetLocationDataFromGPS(self.ffNodeDict[ffNodeMAC]['Longitude'],self.ffNodeDict[ffNodeMAC]['Latitude'])

                ZipCode = self.ffNodeDict[ffNodeMAC]['ZIP']

                if ZipCode is not None and ZipTemplate.match(ZipCode):
                    (ZipRegion,ZipSegment) = LocationInfo.GetLocationDataFromZIP(ZipCode)

                    if ZipRegion is None or ZipSegment is None:
                        print('++ Unknown ZIP-Code:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode)
                    else:  # valid ZIP-Code
                        if GpsRegion is None or GpsSegment is None:
                            GpsRegion  = ZipRegion
                            GpsSegment = ZipSegment
#                            print('>>> Segment set by ZIP-Code:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode,'->',lon,'|',lat,'->',GpsSegment)
                        elif ZipSegment != GpsSegment:
                            print('!!!! Segment Mismatch GPS <> ZIP:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',GpsSegment,'<>',ZipSegment)

                    if GpsZipCode is not None and ZipCode != GpsZipCode:
                        print('>>> ZIP-Code Mismatch GPS <> ZIP: %s = \'%s\' -> %s <> %s' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name'],GpsZipCode,ZipCode))
                        self.ffNodeDict[ffNodeMAC]['ZIP'] = GpsZipCode

                elif self.ffNodeDict[ffNodeMAC]['ZIP'] is None:
                    self.ffNodeDict[ffNodeMAC]['ZIP'] = GpsZipCode
                else:
                    print('!!! Invalid ZIP-Code:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode)


                if GpsRegion is not None:
                    self.ffNodeDict[ffNodeMAC]['Region']  = GpsRegion

                if self.ffNodeDict[ffNodeMAC]['SegMode'][:3] == 'fix':        # fixed Segment independent of Location
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = int(self.ffNodeDict[ffNodeMAC]['SegMode'][4:])
                elif self.ffNodeDict[ffNodeMAC]['SegMode'][:3] == 'man':      # manually defined Segment
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = int(self.ffNodeDict[ffNodeMAC]['KeyDir'][3:])
                elif self.ffNodeDict[ffNodeMAC]['SegMode'][:3] == 'mob':      # No specific Segment for mobile Nodes
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = None
                elif self.ffNodeDict[ffNodeMAC]['GluonType'] == NODETYPE_LEGACY:    # Firmware w/o Segment support
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = 0
                else:
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = GpsSegment

        print('... done.\n')
        return True



    #==============================================================================
    # public function "CheckConsistency"
    #
    #
    #==============================================================================
    def CheckConsistency(self,ValidSegmentList):

        print('Checking Consistency of Data ...')

        for ffNodeMAC in self.ffNodeDict.keys():
            if self.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN:

                if self.ffNodeDict[ffNodeMAC]['Name'] is None:
                    print('!! Hostname is None: %s %s' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC))
                elif BadNameTemplate.match(self.ffNodeDict[ffNodeMAC]['Name']):
                    print('!! Invalid ffNode Hostname: %s = %s -> \'%s\'' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Status'],self.ffNodeDict[ffNodeMAC]['Name']))

                #----- Special TP-Link CPE Handling -----
                if (self.ffNodeDict[ffNodeMAC]['Hardware'].lower().startswith('tp-link cpe') and
                    (self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_MTU_1340 or self.ffNodeDict[ffNodeMAC]['Firmware'][:14] < '1.4+2018-06-24')):
                    print('++ Old CPE found: %s %s = \'%s\'' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = CPE_TEMP_SEGMENT
                    self.ffNodeDict[ffNodeMAC]['SegMode'] = 'fix %02d' % (CPE_TEMP_SEGMENT)

                if self.ffNodeDict[ffNodeMAC]['FastdGW'] is not None:   # Node has VPN-Connection to Gateway
                    if self.ffNodeDict[ffNodeMAC]['KeyDir'] > 'vpn08' and self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_DNS_SEGASSIGN:
                        self.ffNodeDict[ffNodeMAC]['GluonType'] = NODETYPE_DNS_SEGASSIGN
                        print('++ Node has Gluon with DNS-SegAssign: %s / %s = \'%s\'' % ( self.ffNodeDict[ffNodeMAC]['KeyDir'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                    elif self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_SEGMENT_LIST:
                        self.ffNodeDict[ffNodeMAC]['GluonType'] = NODETYPE_SEGMENT_LIST
                        print('++ Node has newer Gluon as expected: %s / %s = \'%s\'' % ( self.ffNodeDict[ffNodeMAC]['KeyDir'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                    if self.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_ONLINE_VPN:
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                        print('++ Node has active VPN-Connection: %s / %s = \'%s\'' % (self.ffNodeDict[ffNodeMAC]['KeyDir'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                if self.ffNodeDict[ffNodeMAC]['Status'] == NODESTATE_ONLINE_VPN:
                    if self.ffNodeDict[ffNodeMAC]['KeyDir'] == '':
                        print('!! Uplink w/o Key: %s %s = \'%s\'' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH
                    elif self.ffNodeDict[ffNodeMAC]['Segment'] is None:
                        print('!! Segment is None: %s = \'%s\'' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                        self.ffNodeDict[ffNodeMAC]['Segment'] = int(self.ffNodeDict[ffNodeMAC]['KeyDir'][3:])
                    elif self.ffNodeDict[ffNodeMAC]['Segment'] != int(self.ffNodeDict[ffNodeMAC]['KeyDir'][3:]):
                        print('!! Segment <> KeyDir: %s = \'%s\': Seg.%02d <> %s' % (
                            ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name'],self.ffNodeDict[ffNodeMAC]['Segment'],self.ffNodeDict[ffNodeMAC]['KeyDir']))
                        self.ffNodeDict[ffNodeMAC]['Segment'] = int(self.ffNodeDict[ffNodeMAC]['KeyDir'][3:])
                else:
                    for NeighbourMAC in self.ffNodeDict[ffNodeMAC]['Neighbours']:
                        if GwMacTemplate.match(NeighbourMAC):
                            print('!! GW-Connection w/o Uplink: %s %s = \'%s\'' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                if self.ffNodeDict[ffNodeMAC]['DestSeg'] is not None:
                    if (self.ffNodeDict[ffNodeMAC]['KeyDir'] != ''
                    and self.ffNodeDict[ffNodeMAC]['DestSeg'] != int(self.ffNodeDict[ffNodeMAC]['KeyDir'][3:])
                    and self.ffNodeDict[ffNodeMAC]['SegMode'] == 'auto'):
                        print('++ Wrong Segment:   %s %s = \'%s\': %02d -> %02d %s' % (
                            self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name'],int(self.ffNodeDict[ffNodeMAC]['KeyDir'][3:]),
                            self.ffNodeDict[ffNodeMAC]['DestSeg'],self.ffNodeDict[ffNodeMAC]['SegMode']))

                    if self.ffNodeDict[ffNodeMAC]['DestSeg'] > 8 and self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_DNS_SEGASSIGN:
                        print('!! Invalid Segment for Gluon-Type %d: >%s< %s = \'%s\' -> Seg. %02d' % (
                            self.ffNodeDict[ffNodeMAC]['GluonType'],self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name'],
                            self.ffNodeDict[ffNodeMAC]['DestSeg']))
                    elif self.ffNodeDict[ffNodeMAC]['DestSeg'] == 0:
                        print('!! Legacy Node found: %s %s = \'%s\'' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_UNKNOWN    # ignore this Node Data

                if self.__IsOnline(ffNodeMAC):
                    if self.ffNodeDict[ffNodeMAC]['Segment'] is None:
                        print('!! Segment is None: %s %s = \'%s\'' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_UNKNOWN    # ignore this Node Data

                    elif self.ffNodeDict[ffNodeMAC]['Segment'] not in ValidSegmentList:
                        print('>>> Unknown Segment:   %s %s = \'%s\' in Seg.%02d' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Segment']))
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_UNKNOWN    # ignore this Node Data

        print('... done.\n')
        return



    #=========================================================================
    # public function "CheckNodesInNodesDNS"
    #
    #   Returns True if everything is OK
    #
    #=========================================================================
    def CheckNodesInNodesDNS(self,DnsAccDict):

        DnsZone     = None
        DnsUpdate   = None
        NodeDnsDict = {}

        print('\nChecking DNS Zone \"nodes\" ...')

        try:
            DnsResolver = dns.resolver.Resolver()
            DnsServerIP = DnsResolver.query('%s.' % (DnsAccDict['Server']),'a')[0].to_text()
            DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,FreifunkNodeDomain))
            DnsKeyRing  = dns.tsigkeyring.from_text( {DnsAccDict['ID'] : DnsAccDict['Key']} )
            DnsUpdate   = dns.update.Update(FreifunkNodeDomain, keyring = DnsKeyRing, keyname = DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')
        except:
            self.__alert('!! ERROR on accessing DNS Zone: '+FreifunkNodeDomain)
        else:
            #---------- Loading Node DNS Entries ----------
            print('Loading Node DNS Entries ...')
            for DnsName, NodeData in DnsZone.nodes.items():
                for DnsRecord in NodeData.rdatasets:
                    DnsNodeID = DnsName.to_text()

                    if PeerTemplate.match(DnsNodeID) and DnsRecord.rdtype == dns.rdatatype.AAAA:
                        NodeIPv6 = None

                        for DnsAnswer in DnsRecord:
                            IPv6 = DnsAnswer.to_text()

                            if ffsIPv6Template.match(IPv6):
                                if NodeIPv6 is None:
                                    NodeIPv6 = IPv6
                                else:
                                    self.__alert('!! Duplicate DNS Result: '+DnsNodeID+' = '+NodeIPv6+' + '+IPv6)
                            else:
                                self.__alert('!! Invalid DNS IPv6 result: '+DnsNodeID+' = '+IPv6)

                        if NodeIPv6 is not None:
                            NodeDnsDict[DnsNodeID] = NodeIPv6

            #---------- Check ffNodeDict for missing DNS entries ----------
            print('Checking ffNodeDict against DNS ...')
            iChanged = 0

            for ffNodeMAC in self.ffNodeDict:
                if self.ffNodeDict[ffNodeMAC]['IPv6'] is not None:
                    DnsNodeID = 'ffs-' + ffNodeMAC.replace(':','')

                    if DnsNodeID in NodeDnsDict:
                        if (NodeDnsDict[DnsNodeID] != self.ffNodeDict[ffNodeMAC]['IPv6'].replace('::',':0:')) and (iChanged < 100):
                            DnsUpdate.replace(DnsNodeID, 120, 'AAAA',self.ffNodeDict[ffNodeMAC]['IPv6'])
                            print(DnsNodeID,NodeDnsDict[DnsNodeID],'->',self.ffNodeDict[ffNodeMAC]['IPv6'])
                            iChanged += 1
                    else:
                        DnsUpdate.add(DnsNodeID, 120, 'AAAA',self.ffNodeDict[ffNodeMAC]['IPv6'])

            if len(DnsUpdate.index) > 1:
                dns.query.tcp(DnsUpdate,DnsServerIP)
                print('DNS-Updates =',iChanged)

        print('... done.\n')
        return
