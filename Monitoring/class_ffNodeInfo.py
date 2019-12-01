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
import socket
import urllib.request
import time
import datetime
import calendar
import json
import re
import hashlib

from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
from glob import glob

import dns.resolver
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.update

from dns.rdataclass import *
from dns.rdatatype import *



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------
YANIC_VERSIONS     = ['1.0.0']

MaxInactiveTime    = 10 * 86400     # 10 Days (in Seconds)
MaxOfflineTime     = 30 * 60        # 30 Minutes (in Seconds)
MaxStatusAge       = 15 * 60        # 15 Minutes (in Seconds)

MinNodesCount      = 1000           # Minimum number of Nodes

FreifunkNodeDomain = 'nodes.freifunk-stuttgart.de'

NodeDictName   = 'NodeDict.json'      # Node Database
MacDictName    = 'MacDict.json'       # MAC Translation Dictionary
Region2ZipName = 'Region2ZIP.json'    # Regions with ZIP Codes of Baden-Wuerttemberg
Zip2GpsName    = 'ZipLocations.json'  # GPS location of ZIP-Areas based on OpenStreetMap and OpenGeoDB
ZipGridName    = 'ZipGrid.json'       # Grid of ZIP Codes from Baden-Wuerttemberg


ffsIPv6Template   = re.compile('^fd21:b4dc:4b[0-9]{2}:0?:')

GwNameTemplate    = re.compile('^gw[01][0-9]{1,2}')
GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[1-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate  = re.compile('^02:00:(3[1-9])(:[0-9a-f]{2}){3}')
GwIdTemplate      = re.compile('^0200(3[1-9])([0-9a-f]{2}){3}')

MacAdrTemplate    = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
McastMacTemplate  = re.compile('^(00(:00){5})|(ff(:ff){5})|(33:33(:[0-9a-f]{2}){4})|(01:00:5e:[0-7][0-9a-f](:[0-9a-f]{2}){2})')
NodeIdTemplate    = re.compile('^[0-9a-f]{12}$')

PeerTemplate      = re.compile('^ffs-[0-9a-f]{12}')
PeerTemplate1     = re.compile('^ffs[-_][0-9a-f]{12}')
PeerTemplate2     = re.compile('^ffs[0-9a-f]{12}')

ZipTemplate       = re.compile('^[0-9]{5}$')
SegmentTemplate   = re.compile('^[0-9]{2}$')
LocationTemplate  = re.compile('[0-9]{1,2}[.][0-9]{3,}')

KeyDirTemplate    = re.compile('^vpn[0-9]{2}$')
FastdKeyTemplate  = re.compile('^[0-9a-f]{64}$')
BadNameTemplate   = re.compile('.*[|/\\<>]+.*')

NODETYPE_UNKNOWN       = 0
NODETYPE_LEGACY        = 1
NODETYPE_SEGMENT_LIST  = 2
NODETYPE_DNS_SEGASSIGN = 3
NODETYPE_MTU_1340      = 4

NODESTATE_UNKNOWN      = '?'
NODESTATE_OFFLINE      = '#'
NODESTATE_ONLINE_MESH  = ' '
NODESTATE_ONLINE_VPN   = 'V'





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
        self.__LoadAlfredData()           # Load Node Info from Alfred

        self.__CheckNodeHostnames()       # Check for invalid letters in hostnames
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



    #=======================================================================
    # function "GenerateGluonMACs(MainMAC)"
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
    #=======================================================================
    def GenerateGluonMACs(self,MainMAC):

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

        GluonMacList = self.GenerateGluonMACs(MainMAC)

        if MeshMAC is not None:
            if MeshMAC not in GluonMacList and MeshMAC != MainMAC:
                GluonMacList.append(MeshMAC)    # not from Gluon MAC schema

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



    #==============================================================================
    # Method "IsOnline"
    #
    #   True = Node is Online
    #==============================================================================
    def IsOnline(self,ffNodeMAC):

        if ffNodeMAC in self.ffNodeDict:
            OnlineState = self.ffNodeDict[ffNodeMAC]['Status'] in [ NODESTATE_ONLINE_MESH, NODESTATE_ONLINE_VPN ]
        else:
            OnlineState = False

        return OnlineState



    #=========================================================================
    # Method "WriteNodeDict"
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



    #-------------------------------------------------------------
    # private function "__LoadNodeDict"
    #
    #   Load ffNodeDict
    #-------------------------------------------------------------
    def __LoadNodeDict(self):

        print('Loading',NodeDictName,'...')
        UnixTime = int(time.time())
        NodeCount = 0

        try:
            JsonFile = open(os.path.join(self.__DatabasePath,NodeDictName), mode='r')
            jsonNodeDict = json.load(JsonFile)
            JsonFile.close()

        except:
            print('\n!! Error on Reading %s !!\n' % (NodeDictName))

        else:
            for ffNodeMAC in jsonNodeDict:
                if (UnixTime - jsonNodeDict[ffNodeMAC]['last_online']) <= MaxInactiveTime:

                    self.ffNodeDict[ffNodeMAC] = {
                        'Name': jsonNodeDict[ffNodeMAC]['Name'],
                        'Hardware': '- unknown -',
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
                        'MeshMACs': [],
                        'IPv6': jsonNodeDict[ffNodeMAC]['IPv6'],
                        'Segment': jsonNodeDict[ffNodeMAC]['Segment'],
                        'SegMode': 'auto',
                        'KeyDir': '',
                        'KeyFile': '',
                        'FastdKey': '',
                        'InCloud': None,
                        'Neighbours': [],
                        'Owner': jsonNodeDict[ffNodeMAC]['Owner']
                    }

                    NodeCount += 1
                    self.__AddGluonMACs(ffNodeMAC,None)

                    if (UnixTime - jsonNodeDict[ffNodeMAC]['last_online']) > MaxOfflineTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_OFFLINE
                    else:
                        self.ffNodeDict[ffNodeMAC]['Neighbours'] = jsonNodeDict[ffNodeMAC]['Neighbours']

        print('... %d Nodes done.\n' % (NodeCount))
        return NodeCount




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
    def __ProcessResponddData(self,NodeDict,UnixTime,DateFormat):

        if 'lastseen' not in NodeDict:
            print('+++ Invalid Record!',NodeDict)

        LastSeen = int(calendar.timegm(time.strptime(NodeDict['lastseen'], DateFormat)))

        if (UnixTime - LastSeen) > MaxInactiveTime:  return False    # Data is obsolete


        if (('nodeinfo' not in NodeDict) or
            ('statistics' not in NodeDict) or
            ('neighbours' not in NodeDict)):
#            print('+++ Invalid Record!',NodeDict)
            return False

        if (('node_id' not in NodeDict['nodeinfo']) or
            ('software' not in NodeDict['nodeinfo']) or
            ('hostname' not in NodeDict['nodeinfo']) or
            ('network' not in NodeDict['nodeinfo'])):
            print('+++ NodeInfo broken!',NodeDict['nodeinfo'])
            return False

        ffNodeID = NodeDict['nodeinfo']['node_id'].strip().lower()

        if GwIdTemplate.match(ffNodeID):
            print('++ Gateway Data found: %s' % (ffNodeID))
            return False

        if (('firmware' not in NodeDict['nodeinfo']['software']) or
            ('release' not in NodeDict['nodeinfo']['software']['firmware']) or
            (NodeDict['nodeinfo']['software']['firmware']['release'] is None) or
            ('mac' not in NodeDict['nodeinfo']['network'])):
            print('++ Broken Data in Record %s !' % (ffNodeID))
            print(NodeDict)
            return False

        if NodeDict['nodeinfo']['node_id'] != NodeDict['statistics']['node_id']:
            print('++ NodeID-Mismatch: nodeinfo = %s / statistics = %s' %
                     (NodeDict['nodeinfo']['node_id'],NodeDict['statistics']['node_id']))
            return False

        if NodeDict['neighbours'] is not None:
            if NodeDict['nodeinfo']['node_id'] != NodeDict['neighbours']['node_id']:
                print('++ NodeID-Mismatch: nodeinfo = %s / neighbours = %s' % (NodeDict['nodeinfo']['node_id'],NodeDict['neighbours']['node_id']))
                return False


        ffNodeMAC = NodeDict['nodeinfo']['network']['mac'].strip().lower()

        if not MacAdrTemplate.match(ffNodeMAC):
            print('!! Invalid MAC Format: %s -> %s' % (ffNodeID,ffNodeMAC))
            return False

        if GwAllMacTemplate.match(ffNodeMAC):  return False    # Data is from Gateway

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
                'FastdKey': '',
                'InCloud': None,
                'Neighbours': [],
                'Owner': None
            }

        if LastSeen < self.ffNodeDict[ffNodeMAC]['last_online']:  return False    # Newer Node info already existing ...


        #---------- Current Data of Node will be used ----------
        self.ffNodeDict[ffNodeMAC]['Name']        = NodeDict['nodeinfo']['hostname']
        self.ffNodeDict[ffNodeMAC]['last_online'] = LastSeen
        self.ffNodeDict[ffNodeMAC]['Clients']     = 0

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
                self.ffNodeDict[ffNodeMAC]['ZIP'] = str(NodeDict['nodeinfo']['location']['zip'])[:5]

        if 'custom_fields' in NodeDict:
            if 'zip' in NodeDict['custom_fields']:
                self.ffNodeDict[ffNodeMAC]['ZIP'] = str(NodeDict['custom_fields']['zip'])[:5]

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


        if (UnixTime - LastSeen) > MaxOfflineTime:
            self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_OFFLINE
        else:
            #----- Node is online -----
            if NodeDict['neighbours'] is not None:
                for InterfaceType in ['batadv','wifi']:
                    if InterfaceType in NodeDict['neighbours']:
                        for MeshMAC in NodeDict['neighbours'][InterfaceType]:

                            if 'neighbours' in NodeDict['neighbours'][InterfaceType][MeshMAC]:
                                for ffNeighbour in NodeDict['neighbours'][InterfaceType][MeshMAC]['neighbours']:
                                    if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                        (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                        self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

            if 'addresses' in NodeDict['nodeinfo']['network']:
                for NodeAddress in NodeDict['nodeinfo']['network']['addresses']:
                    if ffsIPv6Template.match(NodeAddress):
                        self.ffNodeDict[ffNodeMAC]['IPv6'] = NodeAddress

            if 'gateway' in NodeDict['statistics']:
                if GwNewMacTemplate.match(NodeDict['statistics']['gateway']):
                    self.ffNodeDict[ffNodeMAC]['Segment'] = int(NodeDict['statistics']['gateway'][9:11])

            if 'mesh_vpn' in NodeDict['statistics']:
                if 'groups' in NodeDict['statistics']['mesh_vpn']:
                    if 'backbone' in NodeDict['statistics']['mesh_vpn']['groups']:
                        if 'peers' in NodeDict['statistics']['mesh_vpn']['groups']['backbone']:
                            GWpeers = NodeDict['statistics']['mesh_vpn']['groups']['backbone']['peers']

                            for Uplink in GWpeers:
                                if GWpeers[Uplink] is not None:
                                    if 'established' in GWpeers[Uplink]:
                                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN

            if 'uptime' in NodeDict['statistics']:
                self.ffNodeDict[ffNodeMAC]['Uptime'] = NodeDict['statistics']['uptime']

            if not self.IsOnline(ffNodeMAC) and self.ffNodeDict[ffNodeMAC]['Segment'] is not None:
                self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH
#                print('++ Node set as online (%d - %d): %s = \'%s\'' % (UnixTime,LastSeen,ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

        self.__AddGluonMACs(ffNodeMAC,None)
        self.ffNodeDict[ffNodeMAC]['Firmware']  = NodeDict['nodeinfo']['software']['firmware']['release']
        self.ffNodeDict[ffNodeMAC]['GluonType'] = self.__SetSegmentAwareness(self.ffNodeDict[ffNodeMAC]['Firmware'])

        return (self.ffNodeDict[ffNodeMAC]['last_online'] == LastSeen)



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

        UnixTime = int(time.time())
        InfoTime = None
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

        if (UnixTime - InfoTime) > MaxStatusAge:
            self.__alert('++ Yanic raw.json is too old: %d Sec.!' % (UnixTime - InfoTime))
            return


        print('Analysing raw.json (%d Records, Yanic Data Age = %d Sec.) ...' % (len(RawJsonDict['nodes']),UnixTime - InfoTime))

        for NodeDict in RawJsonDict['nodes']:
            if self.__ProcessResponddData(NodeDict,UnixTime,'%Y-%m-%dT%H:%M:%S%z'):
                UsedNodesCount += 1
                ffNodeMAC = NodeDict['nodeinfo']['network']['mac'].strip().lower()

                if self.ffNodeDict[ffNodeMAC]['last_online'] > NewestTime:
                    NewestTime = self.ffNodeDict[ffNodeMAC]['last_online']

                if self.IsOnline(ffNodeMAC):
                    OnlineNodesCount += 1

        print('... %d Nodes selected, online = %d (Age = %d sec.)\n' % (UsedNodesCount,OnlineNodesCount,UnixTime-NewestTime))

        if UsedNodesCount > MinNodesCount and (UnixTime - NewestTime) < MaxStatusAge:
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

        UnixTime = int(time.time())
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

            self.__alert('++ Error on loading raw.json !!!\n')
            return


        print('Analysing raw.json (%d Records) ...' % (len(RawJsonDict)))

        for NodeIdx in RawJsonDict:
            if self.__ProcessResponddData(RawJsonDict[NodeIdx],UnixTime,'%Y-%m-%dT%H:%M:%S.%fZ'):
                UsedNodesCount += 1
                ffNodeMAC = RawJsonDict[NodeIdx]['nodeinfo']['network']['mac'].strip().lower()

                if self.ffNodeDict[ffNodeMAC]['last_online'] > NewestTime:
                    NewestTime = self.ffNodeDict[ffNodeMAC]['last_online']

                if self.IsOnline(ffNodeMAC):
                    OnlineNodesCount += 1

        print('... %d Nodes selected, online = %d (Age = %d sec.)\n' % (UsedNodesCount,OnlineNodesCount,UnixTime-NewestTime))

        if UsedNodesCount > MinNodesCount and (UnixTime - NewestTime) < MaxStatusAge:
            self.AnalyseOnly = False

        return



    #-------------------------------------------------------------
    # private function "__LoadAlfredData"
    #
    #   Load and analyse nodesdb.json from Alfred
    #
    # jsonDbDict <- nodesdb.json
    #
    #-------------------------------------------------------------
    def __LoadAlfredData(self):

        print('Loading nodesdb.json from Alfred ...')

        if 'AlfredData' not in self.__AccountsDict:
            self.__alert('++ Missing URL to access Alfred nodesdb.json !!!\n')
            return

        NewNodesCount = 0
        UpdatedNodesCount = 0
        UnixTime = 0
        NewestTime = 0

        jsonDbDict = None
        Retries = 3

        while jsonDbDict is None and Retries > 0:
            Retries -= 1
            UnixTime = int(time.time())

            try:
                NodesDbJsonHTTP = urllib.request.urlopen(self.__AccountsDict['AlfredData']['URL'],timeout=10)
                HttpDate = int(calendar.timegm(time.strptime(NodesDbJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = UnixTime - HttpDate

                print('... json Age = %d sec.' %(StatusAge))

                if StatusAge > MaxStatusAge:
                    NodesDbJsonHTTP.close()
                    print('++ nodesdb.json is too old !!!\n')
                    return

                jsonDbDict = json.loads(NodesDbJsonHTTP.read().decode('utf-8'))
                NodesDbJsonHTTP.close()
            except:
                print('** need retry ...')
                jsonDbDict = None
                time.sleep(2)

        if jsonDbDict is None:
            print('++ Error on loading nodesdb.json !!!\n')
            return


        print('Analysing nodesdb.json (%d records) ...' % (len(jsonDbDict)))

        for DbIndex in jsonDbDict:
            NodeNets  = jsonDbDict[DbIndex]['network']
            ffNodeMAC = jsonDbDict[DbIndex]['network']['mac'].strip().lower()

            if not MacAdrTemplate.match(DbIndex) or not MacAdrTemplate.match(ffNodeMAC):
                print('++ ERROR nodesdb.json ffNode Format: %s -> %s' % (DbIndex,ffNodeMAC))
            else:
                if GwAllMacTemplate.match(ffNodeMAC):
                    print('++ GW in nodesdb.json: %s -> %s' % (DbIndex,ffNodeMAC))
                elif (UnixTime - jsonDbDict[DbIndex]['last_online']) <= MaxInactiveTime:

                    if jsonDbDict[DbIndex]['last_online'] > NewestTime:
                        NewestTime = jsonDbDict[DbIndex]['last_online']

                    if ffNodeMAC not in self.ffNodeDict:
                        NewNodesCount += 1
                        print('++ New Node: %s = %s' % (ffNodeMAC,jsonDbDict[DbIndex]['hostname']))

                        self.ffNodeDict[ffNodeMAC] = {
                            'Name': jsonDbDict[DbIndex]['hostname'],
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
                            'FastdKey': '',
                            'InCloud': None,
                            'Neighbours': [],
                            'Owner': None
                        }

                    elif jsonDbDict[DbIndex]['last_online'] <= self.ffNodeDict[ffNodeMAC]['last_online']:  continue    # Newest info alredy available ...


                    UpdatedNodesCount += 1
                    self.ffNodeDict[ffNodeMAC]['last_online'] = jsonDbDict[DbIndex]['last_online']

                    if jsonDbDict[DbIndex]['status'] == 'online' and (UnixTime - jsonDbDict[DbIndex]['last_online']) <= MaxOfflineTime:
                        if not self.IsOnline(ffNodeMAC):
                            self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_MESH

                        if 'hardware' in jsonDbDict[DbIndex]:
                            if 'model' in jsonDbDict[DbIndex]['hardware']:
                                self.ffNodeDict[ffNodeMAC]['Hardware'] = jsonDbDict[DbIndex]['hardware']['model']

                        if 'gateway' in jsonDbDict[DbIndex]:
                            if GwNewMacTemplate.match(jsonDbDict[DbIndex]['gateway']):
                                self.ffNodeDict[ffNodeMAC]['Segment']= int(jsonDbDict[DbIndex]['gateway'][9:11])

                        if 'segment' in jsonDbDict[DbIndex] and jsonDbDict[DbIndex]['segment'] is not None:
                            if self.ffNodeDict[ffNodeMAC]['Segment'] is None:
                                self.ffNodeDict[ffNodeMAC]['Segment'] = int(jsonDbDict[DbIndex]['segment'])
                            elif self.ffNodeDict[ffNodeMAC]['Segment'] != int(jsonDbDict[DbIndex]['segment']):
                                print('!! Segment mismatch: %s %s %02d <> %02d = %s' %
                                    (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Segment'],int(jsonDbDict[DbIndex]['segment']),self.ffNodeDict[ffNodeMAC]['Name']))

                        if 'neighbours' in jsonDbDict[DbIndex]:
                            for ffNeighbour in jsonDbDict[DbIndex]['neighbours']:
                                if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                    (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                    self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

                        if 'addresses' in jsonDbDict[DbIndex]['network']:
                            for NodeAddress in jsonDbDict[DbIndex]['network']['addresses']:
                                if ffsIPv6Template.match(NodeAddress):
                                    self.ffNodeDict[ffNodeMAC]['IPv6'] = NodeAddress

                    else:
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_OFFLINE


                    if 'location' in jsonDbDict[DbIndex]:
                        if 'latitude' in jsonDbDict[DbIndex]['location'] and 'longitude' in jsonDbDict[DbIndex]['location']:
                            self.ffNodeDict[ffNodeMAC]['Latitude']  = jsonDbDict[DbIndex]['location']['latitude']
                            self.ffNodeDict[ffNodeMAC]['Longitude'] = jsonDbDict[DbIndex]['location']['longitude']

                        if 'zip' in jsonDbDict[DbIndex]['location']:
                            self.ffNodeDict[ffNodeMAC]['ZIP'] = str(jsonDbDict[DbIndex]['location']['zip'])[:5]

                    if 'mesh_interfaces' in NodeNets:
                        for MeshMAC in NodeNets['mesh_interfaces']:
                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                    if 'mesh' in NodeNets:
                        if 'bat0' in NodeNets['mesh']:
                            if 'interfaces' in NodeNets['mesh']['bat0']:
                                for InterfaceType in NodeNets['mesh']['bat0']['interfaces']:
                                    if InterfaceType in ['tunnel','wireless','other']:
                                        for MeshMAC in NodeNets['mesh']['bat0']['interfaces'][InterfaceType]:
                                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                    if ffNodeMAC not in self.MAC2NodeIDDict:
                        self.__AddGluonMACs(ffNodeMAC,None)

                    if 'software' in jsonDbDict[DbIndex]:
                        if 'firmware' in jsonDbDict[DbIndex]['software']:
                            if 'release' in jsonDbDict[DbIndex]['software']['firmware']:
                                self.ffNodeDict[ffNodeMAC]['Firmware']  = jsonDbDict[DbIndex]['software']['firmware']['release']
                                self.ffNodeDict[ffNodeMAC]['GluonType'] = self.__SetSegmentAwareness(self.ffNodeDict[ffNodeMAC]['Firmware'])

        print('... done. Newest Info = %d Sec. / New Nodes = %d / Updated Nodes = %d\n' % (UnixTime-NewestTime,NewNodesCount,UpdatedNodesCount))
        return



    #-------------------------------------------------------------
    # private function "__CheckNodeHostnames"
    #
    #     Checking Hostnames of Nodes
    #
    #-------------------------------------------------------------
    def __CheckNodeHostnames(self):

        print('Checking Hostnames of Nodes (%d Records) ...' % (len(self.ffNodeDict)))

        for ffNodeMAC in self.ffNodeDict:
            if self.ffNodeDict[ffNodeMAC]['Name'] is None:
                print('!! Hostname is None: %s %s' % (self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC))
            elif BadNameTemplate.match(self.ffNodeDict[ffNodeMAC]['Name']):
                print('!! Invalid ffNode Hostname: %s = %s -> \'%s\'' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

        print('... done.\n')
        return



    #=========================================================================
    # Method "AddFastdInfo"
    #
    #   Add fastd-Infos for Nodes { 'KeyDir','SegMode','VpnMAC','PeerMAC','PeerName','PeerKey' }
    #
    #=========================================================================
    def AddFastdInfos(self,FastdKeyDict):

        newNodes = 0
        addedInfos = 0
        print('Merging fastd-Infos to Nodes ...')

        for KeyFileName in FastdKeyDict:
            FastdKeyInfo = FastdKeyDict[KeyFileName]
            ffNodeMAC = FastdKeyInfo['PeerMAC']

            if not MacAdrTemplate.match(ffNodeMAC):
                print('!! Bad PeerMAC: %s' % (ffNodeMAC))
            else:
                if MacAdrTemplate.match(FastdKeyInfo['VpnMAC']):   # Node is connected to Gateway ...
                    if ffNodeMAC not in self.ffNodeDict:
                        self.ffNodeDict[ffNodeMAC] = {
                            'Name': FastdKeyInfo['PeerName'],
                            'Hardware': '- unknown -',
                            'Status': NODESTATE_ONLINE_VPN,
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
                            'Segment': int(FastdKeyInfo['KeyDir'][3:]),
                            'SegMode': None,
                            'KeyDir': None,
                            'KeyFile': None,
                            'FastdKey': None,
                            'InCloud': None,
                            'Neighbours': [],
                            'Owner': None
                        }

                        print('++ Node added: %s / %s = \'%s\'' % (FastdKeyInfo['KeyDir'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))
                        newNodes += 1

                    if FastdKeyInfo['KeyDir'] > 'vpn08' and self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_DNS_SEGASSIGN:
                        self.ffNodeDict[ffNodeMAC]['GluonType'] = NODETYPE_DNS_SEGASSIGN
                    elif self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_SEGMENT_LIST:
                        self.ffNodeDict[ffNodeMAC]['GluonType'] = NODETYPE_SEGMENT_LIST

                    if self.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_ONLINE_VPN:
                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                        print('++ Node has active VPN-Connection: %s / %s = \'%s\'' % (FastdKeyInfo['KeyDir'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                    if FastdKeyInfo['Timestamp'] > self.ffNodeDict[ffNodeMAC]['last_online']:
                        self.ffNodeDict[ffNodeMAC]['last_online'] = FastdKeyInfo['Timestamp']

                    if self.ffNodeDict[ffNodeMAC]['Segment'] != int(FastdKeyInfo['KeyDir'][3:]):
                        if self.ffNodeDict[ffNodeMAC]['Segment'] is not None:
                            print('!! Segment Mismatch Seg. %02d -> %s on Node %s = \'%s\'' % (
                                self.ffNodeDict[ffNodeMAC]['Segment'],FastdKeyInfo['KeyDir'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                        self.ffNodeDict[ffNodeMAC]['Segment'] = int(FastdKeyInfo['KeyDir'][3:])

                    self.__AddGluonMACs(ffNodeMAC,FastdKeyInfo['VpnMAC'])

                if ffNodeMAC in self.ffNodeDict:
                    self.ffNodeDict[ffNodeMAC]['SegMode']  = FastdKeyInfo['SegMode']
                    self.ffNodeDict[ffNodeMAC]['KeyDir']   = FastdKeyInfo['KeyDir']
                    self.ffNodeDict[ffNodeMAC]['KeyFile']  = KeyFileName
                    self.ffNodeDict[ffNodeMAC]['FastdKey'] = FastdKeyInfo['PeerKey']
                    addedInfos += 1

        print('... %d Keys added (%d new Nodes).\n' % (addedInfos,newNodes))
        return



    #==============================================================================
    # Method "GetBatmanNodeMACs"
    #
    #   Verify Tunnel-MAC / Main-MAC with batman global Translation Table (TG)
    #
    #==============================================================================
    def GetBatmanNodeMACs(self,SegmentList):

        print('\nAnalysing Batman Tables ...')
        UnixTime = int(time.time())
        TotalNodes = 0
        TotalClients = 0

        for ffSeg in SegmentList:
            print('... Segment %02d ...' % (ffSeg))

            BatctlCmd = ('/usr/sbin/batctl -m bat%02d tg' % (ffSeg)).split()    # batman translation table ...

            try:
                BatctlTg = subprocess.run(BatctlCmd, stdout=subprocess.PIPE)
                BatctlResult = BatctlTg.stdout.decode('utf-8')
            except:
                print('++ ERROR accessing batman: %s' % (BatctlCmd))
                BatmanTransTable = None
            else:
                NodeList = []
                ClientList = []

                for BatctlLine in BatctlResult.split('\n'):
                    BatctlInfo = BatctlLine.split()

                    ffNodeMAC = None
                    ffMeshMAC = None
                    VIDfound  = False

                    for InfoColumn in BatctlInfo:
                        if MacAdrTemplate.match(InfoColumn) and not McastMacTemplate.match(InfoColumn) and not GwAllMacTemplate.match(InfoColumn):
                            if ffNodeMAC is None:
                                ffNodeMAC = InfoColumn
                            elif VIDfound:
                                ffMeshMAC = InfoColumn
                                BatmanMacList = self.GenerateGluonMACs(ffNodeMAC)

                                if ffMeshMAC in BatmanMacList:  # Data is from Gluon Node
                                    if ffMeshMAC not in NodeList:
                                        NodeList.append(ffMeshMAC)

                                    self.__AddGluonMACs(ffNodeMAC,ffMeshMAC)

                                    if ffNodeMAC in self.ffNodeDict:
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = ffSeg
                                        self.ffNodeDict[ffNodeMAC]['last_online'] = UnixTime

                                        if not self.IsOnline(ffNodeMAC):
                                            self.ffNodeDict[ffNodeMAC]['Status'] = ' '
                                            print('    >> Node is online: %s = %s' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                                    else:
                                        print('    ++ New Node in Batman TG: Seg.%02d / %s -> %s' % (ffSeg,ffMeshMAC,ffNodeMAC))

                                elif ffNodeMAC in self.ffNodeDict:    # Data of known Node with non-Gluon MAC
                                    print('    !! Special Node in Batman TG: Seg.%02d / %s -> %s = %s' % (ffSeg,ffMeshMAC,ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name']))

                                else:  # Data of Client
                                    if ffNodeMAC not in ClientList:
                                        ClientList.append(ffNodeMAC)

                                break   # not neccessary to parse rest of line

                        elif ffNodeMAC is not None and InfoColumn == '-1':
                            VIDfound  = True

                NodeCount = len(NodeList)
                ClientCount = len(ClientList)
                print('      Nodes = %d / Clients = %d' % (NodeCount,ClientCount))
                TotalNodes   += NodeCount
                TotalClients += ClientCount

        print('\nTotalNodes = %d / TotalClients = %d\n... done.\n' %(TotalNodes,TotalClients))
        return



    #==============================================================================
    # Method "GetUplinkList"
    #
    #   returns UplinkList from NodeList verified by batman traceroute
    #
    #==============================================================================
    def GetUplinkList(self,NodeList,SegmentList):

        print('... Analysing Batman Traceroute: %s -> %s ...' % (NodeList,SegmentList))
        UplinkList = []

        for ffSeg in SegmentList:
            for ffNodeMAC in NodeList:
                BatctlCmd = ('/usr/sbin/batctl -m bat%02d tr %s' % (ffSeg,ffNodeMAC)).split()

                try:
                    BatctlTr = subprocess.run(BatctlCmd, stdout=subprocess.PIPE)
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
                                if MacAdrTemplate.match(BatctlInfo[1]) and not GwAllMacTemplate.match(BatctlInfo[1]):
                                    if BatctlInfo[1] == MeshMAC:
                                        UplinkList.append(ffNodeMAC)
                                        self.ffNodeDict[ffNodeMAC]['Status'] = NODESTATE_ONLINE_VPN
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = ffSeg
                                    break

        return UplinkList



    #==============================================================================
    # Method "DumpMacTable"
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



    #-------------------------------------------------------------
    # private function "__SetupZip2GpsData"
    #
    #     Load ZIP File of OpenGeoDB Project
    #
    #-------------------------------------------------------------
    def __SetupZip2GpsData(self):

        print('Setting up ZIP-to-GPS Data ...')

        Zip2GpsDict = None
        ZipCount = 0

        try:
            with open(os.path.join(self.__DatabasePath,Zip2GpsName), mode='r') as Zip2GpsFile:
                Zip2GpsDict = json.load(Zip2GpsFile)
        except:
            print('!! ERROR on setting up ZIP-to GPS Data')
            Zip2GpsDict = None
        else:
            ZipCount = len(Zip2GpsDict)

        print('... ZIP-Codes loaded: %d\n' % (ZipCount))
        return Zip2GpsDict



    #-------------------------------------------------------------
    # private function "__SetupZipAreaData"
    #
    #     ZipFileDict -> Dictionary of ZIP-Area Files
    #
    #-------------------------------------------------------------
    def __SetupZipAreaData(self):

        print('Setting up ZIP-Area Data ...')

        ZipAreaFiles = glob(os.path.join(self.__GitPath,'vpn*/zip-areas/?????_*.json'))
        ZipFileDict  = {}

        for FileName in ZipAreaFiles:
            ZipCode = os.path.basename(FileName)[:5]
            ZipFileDict[ZipCode] = { 'FileName':FileName, 'Area':os.path.basename(FileName).split(".")[0], 'Segment':int(FileName.split("/")[-3][3:]) }

        if len(ZipFileDict) < 10:
            print('!! ERROR on registering ZIP-Areas: No. of Records = %d\n' % (len(ZipFileDict)))
            ZipFileDict = None
        else:
            print('... ZIP-Areas registered: %d\n' % (len(ZipFileDict)))

        return ZipFileDict



    #-------------------------------------------------------------
    # private function "__SetupZipGridData"
    #
    #     ZipGridDict -> Grid with ZIP-Codes
    #
    #-------------------------------------------------------------
    def __SetupZipGridData(self):

        print('Setting up ZIP-Grid Data ...')

        ZipGridDict = None
        FieldCount  = 0

        try:
            with open(os.path.join(self.__DatabasePath,ZipGridName), mode='r') as ZipGridFile:
                ZipGridDict = json.load(ZipGridFile)
        except:
            print('!! ERROR on setting up ZIP-Grid Data')
            ZipGridDict = None
        else:
            FieldCount = len(ZipGridDict['Fields'])

            lon_min = float(ZipGridDict['Meta']['lon_min'])
            lon_max = float(ZipGridDict['Meta']['lon_max'])
            lat_min = float(ZipGridDict['Meta']['lat_min'])
            lat_max = float(ZipGridDict['Meta']['lat_max'])

            ZipGridDict['Meta']['lon_scale'] = float(ZipGridDict['Meta']['lon_fields']) / (lon_max - lon_min)
            ZipGridDict['Meta']['lat_scale'] = float(ZipGridDict['Meta']['lat_fields']) / (lat_max - lat_min)

        print('... ZIP-Fields loaded: %d\n' % (FieldCount))
        return ZipGridDict



    #-------------------------------------------------------------
    # private function "__GetZipCodeFromGPS"
    #
    #     Get ZIP-Code from GPS using ZIP polygons
    #
    #-------------------------------------------------------------
    def __GetZipCodeFromGPS(self,lon,lat,ZipAreaDict,ZipGridDict):

        ZipCodeResult = None

        if lat is not None and lon is not None:
            x = int((lon - float(ZipGridDict['Meta']['lon_min'])) * ZipGridDict['Meta']['lon_scale'])
            y = int((lat - float(ZipGridDict['Meta']['lat_min'])) * ZipGridDict['Meta']['lat_scale'])

            if ((x >= 0 and x < ZipGridDict['Meta']['lon_fields']) and
                (y >= 0 and y < ZipGridDict['Meta']['lat_fields'])):

                NodeLocation = Point(lon,lat)
                FieldIndex = str(y*ZipGridDict['Meta']['lon_fields'] + x)

                for ZipCode in ZipGridDict['Fields'][FieldIndex]:
                    ZipFileName = ZipAreaDict[ZipCode]['FileName']
                    ZipAreaJson = None

                    with open(ZipFileName,"r") as fp:
                        ZipAreaJson = json.load(fp)

                    if "geometries" in ZipAreaJson:
                        TrackBase = ZipAreaJson["geometries"][0]["coordinates"]
                    elif "coordinates" in ZipAreaJson:
                        TrackBase = ZipJson["coordinates"]
                    else:
                        TrackBase = None
                        print('Problem parsing %s' % ZipFileName)
                        continue

                    AreaMatch = 0

                    for Track in TrackBase:
                        Shape = []

                        for t in Track[0]:
                            Shape.append( (t[0],t[1]) )

                        ZipPolygon = Polygon(Shape)

                        if ZipPolygon.intersects(NodeLocation):
                            AreaMatch += 1

                    if AreaMatch == 1:
                        ZipCodeResult = ZipCode
                        break

        return ZipCodeResult



    #-------------------------------------------------------------
    # private function "__SetupRegionData"
    #
    #     Load Region Json Files and setup polygons
    #
    #-------------------------------------------------------------
    def __SetupRegionData(self):

        print('Setting up Region Data ...')

        RegionDict = {
            'ValidArea': Polygon([ (0.0,45.0),(0.0,60.0),(20.0,60.0),(20.0,45.0) ]),
            'Polygons' : {},
            'Segments' : {},
            'WithZip'  : []
        }


        try:
            with open(os.path.join(self.__DatabasePath,Region2ZipName), mode='r') as Region2ZipFile:
                Region2ZipDict = json.load(Region2ZipFile)
        except:
            print('!! ERROR on loading Region-to-ZIP Data')
        else:
            for Region in Region2ZipDict:
                RegionDict['WithZip'].append(Region)

        JsonFileList = glob(os.path.join(self.__GitPath,'vpn*/regions/*.json'))
        RegionCount = 0

        try:
            for FileName in JsonFileList:
                Region  = os.path.basename(FileName).split('.')[0]
                Segment = int(os.path.dirname(FileName).split('/')[-2][3:])

                if Region[0] == '_':
                    print('!! Invalid File: %s' % FileName)
                    RegionCount = 0
                    break

                else:
                    with open(FileName,'r') as JsonFile:
                        GeoJson = json.load(JsonFile)

                    if 'type' in GeoJson and 'geometries' in GeoJson:
                        TrackBase = GeoJson['geometries'][0]['coordinates']
                    elif 'coordinates' in GeoJson:
                        TrackBase = GeoJson['coordinates']
                    else:
                        TrackBase = None
                        print('Problem parsing %s' % FileName)
                        continue

                    RegionDict['Polygons'][Region] = []
                    RegionDict['Segments'][Region] = Segment
                    RegionCount += 1

                    for Track in TrackBase:
                        Shape = []

                        for t in Track[0]:
                            Shape.append( (t[0],t[1]) )    # t[0] = Longitude = x | t[1] = Latitude = y

                        RegionDict['Polygons'][Region].append(Polygon(Shape))

        except:
            RegionCount = 0

        if RegionCount == 0:
            RegionDict = None
        else:
            for Region in RegionDict['WithZip']:
                if Region not in RegionDict['Polygons']:
                    print('!! Missing Region Polygon: %s' % (Region))

        print('... Region Areas loaded: %d\n' % (RegionCount))
        return RegionDict



    #-------------------------------------------------------------
    # private function "__GetRegionFromGPS"
    #
    #     Get Region from GPS using area polygons
    #
    #-------------------------------------------------------------
    def __GetRegionFromGPS(self,lon,lat,ffNodeMAC,RegionDict):

        GpsRegion = None

        if lat is not None and lon is not None:
            NodeLocation = Point(lon,lat)

            if RegionDict['ValidArea'].intersects(NodeLocation):

                for Region in RegionDict['Polygons']:
                    if Region not in RegionDict['WithZip']:
                        MatchCount = 0

                        for RegionPart in RegionDict['Polygons'][Region]:
                            if RegionPart.intersects(NodeLocation):
                                MatchCount += 1

                        if MatchCount == 1:
                            GpsRegion = Region
                            break

            else:
                print('!! Invalid Location: %s = \'%s\' -> %d | %d' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name'],lon,lat))

        return GpsRegion



    #==============================================================================
    # Method "SetDesiredSegments"
    #
    #   Get Segment from Location (GPS Data or ZIP-Code)
    #==============================================================================
    def SetDesiredSegments(self):

        print('Setting up Desired Segments from GPS Data or ZIP-Code ...')

        isOK = True
        RegionDict  = self.__SetupRegionData()
        Zip2PosDict = self.__SetupZip2GpsData()
        ZipAreaDict = self.__SetupZipAreaData()
        ZipGridDict = self.__SetupZipGridData()

        if RegionDict is None or Zip2PosDict is None or ZipAreaDict is None or ZipGridDict is None:
            self.__alert('!! No Region Data available !!!')
            self.AnalyseOnly = True
            isOK = False
        else:
            for ffNodeMAC in self.ffNodeDict:
                if self.ffNodeDict[ffNodeMAC]['Status'] != NODESTATE_UNKNOWN:
                    lat = None
                    lon = None

                    GpsRegion  = None
                    GpsSegment = None
                    GpsZipCode = None

                    ZipRegion  = None
                    ZipSegment = None
                    ZipCode    = None

                    if LocationTemplate.match(str(self.ffNodeDict[ffNodeMAC]['Latitude'])) and LocationTemplate.match(str(self.ffNodeDict[ffNodeMAC]['Longitude'])):

                        lat = self.ffNodeDict[ffNodeMAC]['Latitude']
                        lon = self.ffNodeDict[ffNodeMAC]['Longitude']

                        if lat < lon:
                            lat = self.ffNodeDict[ffNodeMAC]['Longitude']
                            lon = self.ffNodeDict[ffNodeMAC]['Latitude']

                        while lat > 90.0:    # missing decimal separator
                            lat /= 10.0

                        while lon > 70.0:    # missing decimal separator
                            lon /= 10.0

                        GpsZipCode = self.__GetZipCodeFromGPS(lon,lat,ZipAreaDict,ZipGridDict)

                        if GpsZipCode is not None:
                            GpsRegion  = ZipAreaDict[GpsZipCode]['Area']
                            GpsSegment = ZipAreaDict[GpsZipCode]['Segment']
                        else:
                            GpsRegion = self.__GetRegionFromGPS(lon,lat,ffNodeMAC,RegionDict)

                            if GpsRegion is not None:
                                GpsSegment = RegionDict['Segments'][GpsRegion]

                    if self.ffNodeDict[ffNodeMAC]['ZIP'] is not None:
                        ZipCode = self.ffNodeDict[ffNodeMAC]['ZIP'][:5]

                        if ZipTemplate.match(ZipCode):

                            if ZipCode in ZipAreaDict:
                                ZipRegion  = ZipAreaDict[ZipCode]['Area']
                                ZipSegment = ZipAreaDict[ZipCode]['Segment']

                            elif ZipCode in Zip2PosDict:
                                lon = Zip2PosDict[ZipCode][0]
                                lat = Zip2PosDict[ZipCode][1]
                                ZipRegion = self.__GetRegionFromGPS(lon,lat,ffNodeMAC,RegionDict)

                                if ZipRegion is None:
                                    print('>>> Unknown ZIP-Region:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode)
                                else:
                                    ZipSegment = RegionDict['Segments'][ZipRegion]
                            else:
                                print('*** Invalid ZIP-Code:  ',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode)

                            if ZipRegion is not None:
                                if GpsRegion is None:
                                    GpsRegion  = ZipRegion
                                    GpsSegment = ZipSegment
#                                    print('>>> Segment set by ZIP-Code:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode,'->',lon,'|',lat,'->',GpsSegment)

                                elif ZipSegment != GpsSegment:
                                    print('!! Segment Mismatch GPS <> ZIP:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',GpsSegment,'<>',ZipSegment)

                        else:
                            print('!! Invalid ZIP-Code:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',ZipCode)

                    if ZipCode is None or ZipSegment is None:
                        self.ffNodeDict[ffNodeMAC]['ZIP'] = GpsZipCode
                    elif GpsZipCode is not None and ZipCode != GpsZipCode:
                        print('>>> ZIP-Code Mismatch GPS <> ZIP: %s = \'%s\' -> %s <> %s' % (ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Name'],GpsZipCode,ZipCode))
                        self.ffNodeDict[ffNodeMAC]['ZIP'] = GpsZipCode

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
                    elif GpsSegment is not None:
                        self.ffNodeDict[ffNodeMAC]['DestSeg'] = GpsSegment

        print('... done.\n')
        return isOK



    #=========================================================================
    # Method "CheckNodesInNodesDNS"
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
