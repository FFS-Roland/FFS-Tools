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
#       raw.json                   -> Node Names and Information                          #
#       nodesdb.json               -> Region = Segment                                    #
#       alfred-json-158.json       -> Nodeinfos                                           #
#       alfred-json-159.json       -> VPN-Uplinks                                         #
#       alfred-json-160.json       -> Neighbors                                           #
#                                                                                         #
#       regions/<segment>/*.json   -> Polygons of Regions                                 #
#       database/ZipLocations.json -> Dict. of ZIP-Codes with related GPS-Positions       #
#       database/ZipGrid.json      -> Dict. of Grids with ZIP-Codes                       #
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

MaxInactiveTime    = 10 * 86400     # 10 Days (in Seconds)
MaxOfflineTime     = 30 * 60        # 30 Minutes (in Seconds)
MaxStatusAge       = 15 * 60        # 15 Minutes (in Seconds)

OnlineStates       = [' ','V']      # online, online with VPN-Uplink

FreifunkNodeDomain = 'nodes.freifunk-stuttgart.de'

NodesDbName    = 'nodesdb.json'
Alfred158Name  = 'alfred-json-158.json'
Alfred159Name  = 'alfred-json-159.json'
Alfred160Name  = 'alfred-json-160.json'

NodeDictName   = 'NodeDict.json'      # Node Database
Region2ZipName = 'Region2ZIP.json'    # Regions with ZIP Codes of Baden-Wuerttemberg
Zip2GpsName    = 'ZipLocations.json'  # GPS location of ZIP-Areas based on OpenStreetMap and OpenGeoDB
ZipGridName    = 'ZipGrid.json'       # Grid of ZIP Codes from Baden-Wuerttemberg


ffsIPv6Template   = re.compile('^fd21:b4dc:4b[0-9a-f]{2}:0:')

GwNameTemplate    = re.compile('^gw[01][0-9]{1,2}')
GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[1-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate  = re.compile('^02:00:(3[1-9])(:[0-9a-f]{2}){3}')

MacAdrTemplate    = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
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

BATMAN_DEBUG_FILES  = '/sys/kernel/debug/batman_adv'
BATMAN_TRANS_TABLE  = 'transtable_global'
BATMAN_ORIGI_TABLE  = 'originators'

NODETYPE_UNKNOWN       = 0
NODETYPE_LEGACY        = 1
NODETYPE_SEGMENT_LIST  = 2
NODETYPE_DNS_SEGASSIGN = 3
NODETYPE_MTU_1340      = 4





class ffNodeInfo:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,AlfredURL,RawAccess,GitPath,DatabasePath):

        # public Attributes
        self.MAC2NodeIDDict = {}       # Dictionary of all Nodes' MAC-Addresses and related Main Address
        self.ffNodeDict     = {}       # Dictionary of Nodes [MainMAC] with their Name, VPN-Uplink
        self.Alerts         = []       # List of  Alert-Messages
        self.AnalyseOnly    = False    # Locking automatic Actions due to inconsistent Data

        # private Attributes
        self.__AlfredURL    = AlfredURL
        self.__RawAccess    = RawAccess
        self.__GitPath      = GitPath
        self.__DatabasePath = DatabasePath

        # Initializations
        socket.setdefaulttimeout(5)

        self.__LoadNodeDict()           # ffNodeDict[ffNodeMAC] -> saved Infos of ffNodes
        self.__LoadNodesDbJson()        # all combined Alfred-Infos from Alfred-Server
        self.__LoadAlfred158Json()      # Alfred - basic infos of the Nodes
        self.__LoadAlfred159Json()      # Alfred - VPN-Uplinks of the Nodes
        self.__LoadAlfred160Json()      # Alfred - Neighbours of the Nodes
        self.__LoadRawJson()            # add or update Info with Data from announced / respondd
        self.__CheckNodeHostnames()     # Check for invalid letters in hostnames
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
    # function "GenerateGluonMACsOld(MainMAC)"
    #
    #   Append self.MAC2NodeIDDict for Gluon <= 2016.1.x
    #
    # reference = Gluon Source:
    #
    #   /package/gluon-core/files/usr/lib/lua/gluon/util.lua
    #
    # function generate_mac(f, i)
    # -- (1, 0): WAN (for mesh-on-WAN)
    # -- (1, 1): LAN (for mesh-on-LAN)
    # -- (2, n): client interface for the n'th radio
    # -- (3, n): adhoc interface for n'th radio)
    # -- (4, 0): mesh VPN
    # -- (5, n): mesh interface for n'th radio (IEEE 802.11s)
    #
    #  m1 = nixio.bit.bor(tonumber(m1, 16), 0x02)
    #  m2 = (tonumber(m2, 16)+f) % 0x100
    #  m3 = (tonumber(m3, 16)+i) % 0x100
    #=======================================================================
    def GenerateGluonMACsOld(self,MainMAC):

        MacRanges = { 1:1, 2:2, 3:2, 4:0, 5:2 }

        m1Main = int(MainMAC[0:2],16)
        m2Main = int(MainMAC[3:5],16)
        m3Main = int(MainMAC[6:8],16)

        m1New = hex(m1Main | 0x02)[2:].zfill(2)

        GluonMacList = []

        for f in MacRanges:
            for i in range(MacRanges[f]+1):
                m2New = hex((m2Main + f) % 0x100)[2:].zfill(2)
                m3New = hex((m3Main + i) % 0x100)[2:].zfill(2)

                GluonMacList.append(m1New + ':' + m2New + ':' + m3New + ':' + MainMAC[9:])

        return GluonMacList



    #=======================================================================
    # function "GenerateGluonMACsNew(MainMAC)"
    #
    #   Append self.MAC2NodeIDDict for Gluon >= 2016.2.x
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
    def GenerateGluonMACsNew(self,MainMAC):

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
    #   add MACs to MAC2NodeIDDict
    #-------------------------------------------------------------
    def __AddGluonMACs(self,MainMAC,MeshMAC):

        if self.ffNodeDict[MainMAC]['Status'] == '?' and self.ffNodeDict[MainMAC]['Name'] == '<killme>':
            return MainMAC   # Node data has to be killed because HW was replaced ...

        if MeshMAC != '':
            GluonMacList = self.GenerateGluonMACsNew(MainMAC)

            if MeshMAC not in GluonMacList:
                GluonMacList = self.GenerateGluonMACsOld(MainMAC)

                if MeshMAC not in GluonMacList:
#                    print('\n!! Invalid Mesh-MAC:',MeshMAC,'->',MainMAC,'= \''+self.ffNodeDict[MainMAC]['Name']+'\'')
                    GluonMacList = [ MeshMAC ]    # neither new nor old mac schema

        else:   # only MainMAC available
            GluonMacList = []

        BadMAC = None

        for NewMAC in GluonMacList:
            if NewMAC in self.MAC2NodeIDDict:
                if self.MAC2NodeIDDict[NewMAC] != MainMAC:
                    print('\n!! MAC-Collision:',NewMAC,'=',MainMAC,'/',MeshMAC,'= \''+self.ffNodeDict[MainMAC]['Name']+'\'')
                    print('  stored Partner:',self.MAC2NodeIDDict[NewMAC],'= \''+self.ffNodeDict[self.MAC2NodeIDDict[NewMAC]]['Name']+'\'')

                    if self.ffNodeDict[MainMAC]['last_online'] > self.ffNodeDict[self.MAC2NodeIDDict[NewMAC]]['last_online']:
                        BadMAC = self.MAC2NodeIDDict[NewMAC]
                        self.MAC2NodeIDDict[NewMAC] = MainMAC

                        for MAC in self.MAC2NodeIDDict:
                            if self.MAC2NodeIDDict[MAC] == BadMAC:
                                self.MAC2NodeIDDict[MAC] = MainMAC

                    else:
                        BadMAC = MainMAC

                    print('>>      Bad Node:',BadMAC,'= \''+self.ffNodeDict[BadMAC]['Name']+'\'')
                    self.ffNodeDict[BadMAC]['Status'] = '?'
#                    self.ffNodeDict[BadMAC]['Name'] = '<killme>'
#                    self.ffNodeDict[BadMAC]['DestSeg'] = 999    # kill this Node
                    self.ffNodeDict[BadMAC]['Neighbours'] = []
                    print()
#                    break

            else:
                self.MAC2NodeIDDict[NewMAC] = MainMAC
                self.ffNodeDict[MainMAC]['MeshMACs'].append(NewMAC)

        return BadMAC



    #-------------------------------------------------------------
    # private function "__SetSegmentAwareness(NodeMAC,NodeSoftwareDict)"
    #
    #   check segment awareness of gluon
    #     0 = unknown
    #     1 = old FW without segmentation
    #     2 = fix segments 1 .. 8
    #     3 = new segment assignment by DNS
    #-------------------------------------------------------------
    def __SetSegmentAwareness(self,NodeMAC,NodeSoftwareDict):

        if 'firmware' in NodeSoftwareDict:
            if 'release' in NodeSoftwareDict['firmware']:
                if NodeSoftwareDict['firmware']['release'] is not None:
                    if NodeSoftwareDict['firmware']['release'][:14] >= '1.3+2017-09-13':
                        self.ffNodeDict[NodeMAC]['GluonType'] = NODETYPE_MTU_1340
                    elif NodeSoftwareDict['firmware']['release'][:14] >= '1.0+2017-02-14':
                        self.ffNodeDict[NodeMAC]['GluonType'] = NODETYPE_DNS_SEGASSIGN
                    elif NodeSoftwareDict['firmware']['release'][:14] >= '0.7+2016.01.02':
                        self.ffNodeDict[NodeMAC]['GluonType'] = NODETYPE_SEGMENT_LIST
                    else:
                        self.ffNodeDict[NodeMAC]['GluonType'] = NODETYPE_LEGACY

        return



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
        jsonNodeDict = None
        NodeCount = 0

        try:
            JsonFile = open(os.path.join(self.__DatabasePath,NodeDictName), mode='r')
            jsonNodeDict = json.load(JsonFile)
            JsonFile.close()

        except:
            print('\n!! Error on Reading',NodeDictName,'!!\n')
            jsonNodeDict = None

        if jsonNodeDict is not None:
            for ffNodeMAC in jsonNodeDict:
                if ((jsonNodeDict[ffNodeMAC]['GluonType'] >= NODETYPE_DNS_SEGASSIGN) or
                    (len(jsonNodeDict[ffNodeMAC]['MeshMACs']) > 0)):

                    self.ffNodeDict[ffNodeMAC] = {
                        'RawKey': None,
                        'Name': jsonNodeDict[ffNodeMAC]['Name'],
                        'Status': jsonNodeDict[ffNodeMAC]['Status'],
                        'last_online': jsonNodeDict[ffNodeMAC]['last_online'],
                        'Clients': 0,
                        'Latitude': jsonNodeDict[ffNodeMAC]['Latitude'],
                        'Longitude': jsonNodeDict[ffNodeMAC]['Longitude'],
                        'ZIP': jsonNodeDict[ffNodeMAC]['ZIP'],
                        'Region': '??',
                        'DestSeg': None,
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
                    self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC

                    if UnixTime - jsonNodeDict[ffNodeMAC]['last_online'] > MaxInactiveTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = '?'
                    elif UnixTime - jsonNodeDict[ffNodeMAC]['last_online'] > MaxOfflineTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = '#'

                    if len(jsonNodeDict[ffNodeMAC]['MeshMACs']) == 0:
                        jsonNodeDict[ffNodeMAC]['MeshMACs'] = self.GenerateGluonMACsNew(ffNodeMAC)

                    for MeshMAC in jsonNodeDict[ffNodeMAC]['MeshMACs']:
                        self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                elif jsonNodeDict[ffNodeMAC]['Status'] != '?':
                    print('!! Bad Entry:',ffNodeMAC,'->',jsonNodeDict[ffNodeMAC]['Status'])

        print('... %d Nodes done.\n' % (NodeCount))
        return



    #-------------------------------------------------------------
    # private function "__LoadNodesDbJson"
    #
    #   Load and analyse nodesdb.json
    #
    # jsonDbDict <- nodesdb.json
    #
    # self.ffNodeDict[ffNodeMAC] -> all Infos of ffNode
    # self.MAC2NodeIDDict[InterfaceMAC] -> ffNodeMAC = Main MAC
    #-------------------------------------------------------------
    def __LoadNodesDbJson(self):

        print('Loading nodesdb.json ...')
        NewestTime = 0
        jsonDbDict = None
        Retries = 3

        while jsonDbDict is None and Retries > 0:
            Retries -= 1
            UnixTime = int(time.time())

            try:
                NodesDbJsonHTTP = urllib.request.urlopen(self.__AlfredURL+NodesDbName,timeout=10)
                HttpDate = int(calendar.timegm(time.strptime(NodesDbJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = UnixTime - HttpDate

                print('>>> Age =',StatusAge,'Sec.')

                if StatusAge > MaxStatusAge:
                    NodesDbJsonHTTP.close()
                    self.__alert('++ nodesdb.json is too old !!!\n')
                    return

                jsonDbDict = json.loads(NodesDbJsonHTTP.read().decode('utf-8'))
                NodesDbJsonHTTP.close()
            except:
                print('** need retry ...')
                jsonDbDict = None
                time.sleep(2)

        if jsonDbDict is None:
#            self.__alert('++ Error on loading nodesdb.json !!!\n')
            print('++ Error on loading nodesdb.json !!!\n')
            return

        print('Analysing nodesdb.json ...',len(jsonDbDict))

        for DbIndex in jsonDbDict:
            NodeNets  = jsonDbDict[DbIndex]['network']
            ffNodeMAC = jsonDbDict[DbIndex]['network']['mac'].strip().lower()

            if not MacAdrTemplate.match(DbIndex) or not MacAdrTemplate.match(ffNodeMAC):
                print('++ ERROR nodesdb.json ffNode Format:',DbIndex,'->',ffNodeMAC)
            else:
                if GwAllMacTemplate.match(ffNodeMAC):
                    print('++ GW in nodesdb.json:',DbIndex,'->',ffNodeMAC)
                else:
                    if ffNodeMAC in self.ffNodeDict:
#                        print('++ Node already stored:',ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Status'],self.ffNodeDict[ffNodeMAC]['last_online'],'->',DbIndex,jsonDbDict[DbIndex]['status'],jsonDbDict[DbIndex]['last_online'])

                        if jsonDbDict[DbIndex]['last_online'] <= self.ffNodeDict[ffNodeMAC]['last_online']:
                            continue    # no newer info available

                        NodeOwner = self.ffNodeDict[ffNodeMAC]['Owner']
                    else:
                        NodeOwner = None

                    self.ffNodeDict[ffNodeMAC] = {
                        'RawKey': None,
                        'Name': jsonDbDict[DbIndex]['hostname'],
                        'Status': '#',
                        'last_online': jsonDbDict[DbIndex]['last_online'],
                        'Clients': 0,
                        'Latitude': None,
                        'Longitude': None,
                        'ZIP': None,
                        'Region': '??',
                        'DestSeg': None,
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
                        'Owner': NodeOwner
                    }

                    self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC

                    if UnixTime - jsonDbDict[DbIndex]['last_online'] > MaxInactiveTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = '?'
                    else:
                        if jsonDbDict[DbIndex]['last_online'] > NewestTime:
                            NewestTime = jsonDbDict[DbIndex]['last_online']

                        if jsonDbDict[DbIndex]['status'] == 'online' and (UnixTime - jsonDbDict[DbIndex]['last_online']) < MaxOfflineTime:
                            self.ffNodeDict[ffNodeMAC]['Status'] = ' '

                            if 'segment' in jsonDbDict[DbIndex] and jsonDbDict[DbIndex]['segment'] is not None:
                                self.ffNodeDict[ffNodeMAC]['Segment'] = int(jsonDbDict[DbIndex]['segment'])

                            if 'gateway' in jsonDbDict[DbIndex]:
                                if jsonDbDict[DbIndex]['gateway'][:9] == '02:00:0a:':
                                    GwSeg = int(jsonDbDict[DbIndex]['gateway'][12:14])
                                elif GwNewMacTemplate.match(jsonDbDict[DbIndex]['gateway']):
                                    GwSeg = int(jsonDbDict[DbIndex]['gateway'][9:11])
                                else:
                                    GwSeg = None

                                if GwSeg is not None:
                                    if self.ffNodeDict[ffNodeMAC]['Segment'] is None:
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = GwSeg
                                    elif self.ffNodeDict[ffNodeMAC]['Segment'] != GwSeg:
                                        print('!! Segment mismatch:',self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Segment'],'<>',GwSeg,'=',self.ffNodeDict[ffNodeMAC]['Name'])

                            if 'neighbours' in jsonDbDict[DbIndex]:
                                for ffNeighbour in jsonDbDict[DbIndex]['neighbours']:
                                    if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                        (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                        self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

                        if 'addresses' in jsonDbDict[DbIndex]['network']:
                            for NodeAddress in jsonDbDict[DbIndex]['network']['addresses']:
                            	if ffsIPv6Template.match(NodeAddress):
                            	    self.ffNodeDict[ffNodeMAC]['IPv6'] = NodeAddress

                    if 'location' in jsonDbDict[DbIndex]:
                        if 'latitude' in jsonDbDict[DbIndex]['location'] and 'longitude' in jsonDbDict[DbIndex]['location']:
                            self.ffNodeDict[ffNodeMAC]['Latitude']  = jsonDbDict[DbIndex]['location']['latitude']
                            self.ffNodeDict[ffNodeMAC]['Longitude'] = jsonDbDict[DbIndex]['location']['longitude']

                        if 'zip' in jsonDbDict[DbIndex]['location']:
                            self.ffNodeDict[ffNodeMAC]['ZIP'] = str(jsonDbDict[DbIndex]['location']['zip'])[:5]

                    if 'mesh_interfaces' in NodeNets:
                        for MeshMAC in NodeNets['mesh_interfaces']:
                            if self.__AddGluonMACs(ffNodeMAC,MeshMAC) is not None:
                                break

                    if 'mesh' in NodeNets:
                        if 'bat0' in NodeNets['mesh']:
                            if 'interfaces' in NodeNets['mesh']['bat0']:
                                for InterfaceType in NodeNets['mesh']['bat0']['interfaces']:
                                    if InterfaceType in ['tunnel','wireless','other']:
                                        for MeshMAC in NodeNets['mesh']['bat0']['interfaces'][InterfaceType]:
                                            if self.__AddGluonMACs(ffNodeMAC,MeshMAC) is not None:
                                                break

                    if 'software' in jsonDbDict[DbIndex]:
                        self.__SetSegmentAwareness(ffNodeMAC,jsonDbDict[DbIndex]['software'])

        if UnixTime - NewestTime > MaxOfflineTime:
            self.__alert('\n>> nodesdb.json has too old contents !!!')

        print('... done.\n')
        return



    #-------------------------------------------------------------
    # Load and analyse alfred-json-158.json
    #
    # Verify self.ffNodeDict:
    #
    #-------------------------------------------------------------
    def __LoadAlfred158Json(self):

        print('Loading alfred-json-158.json ...')
        json158Dict = None
        Retries = 3

        while json158Dict is None and Retries > 0:
            Retries -= 1

            try:
                Afred158HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred158Name,timeout=10)
                HttpDate = int(calendar.timegm(time.strptime(Afred158HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = int(time.time()) - HttpDate

                print('>>> Age =',StatusAge,'Sec.')

                if StatusAge > MaxStatusAge:
                    Afred158HTTP.close()
                    self.__alert('++ alfred-json-158.json is too old !!!\n')
                    self.AnalyseOnly = True
                    return

                json158Dict = json.loads(Afred158HTTP.read().decode('utf-8'))
                Afred158HTTP.close()
            except:
                print('** need retry ...')
                json158Dict = None
                time.sleep(2)

        if json158Dict is None:
            self.__alert('++ Error on loading alfred-json-158.json !!!\n')
            self.AnalyseOnly = True
            return


        print('Analysing alfred-json-158.json ...',len(json158Dict))
        HttpDate -= 300    # 5 minutes delay from Alfred to json-File

        for jsonIndex in json158Dict:
            if ((not 'node_id' in json158Dict[jsonIndex]) or
                (not 'hostname' in json158Dict[jsonIndex]) or
                (not 'network' in json158Dict[jsonIndex]) or
                (not 'software' in json158Dict[jsonIndex])):

                print('!! Alfred-Json-158 Format Error:',jsonIndex)

            else:
                NodeID = json158Dict[jsonIndex]['node_id'].strip().lower()
                NodeMAC = NodeID[0:2] + ':' + NodeID[2:4] + ':' + NodeID[4:6] + ':' + NodeID[6:8] + ':' + NodeID[8:10] + ':' + NodeID[10:12]

                if not MacAdrTemplate.match(NodeMAC):
                    print('!! Invalid NodeMAC:',jsonIndex,'=',NodeMAC)

                elif not GwAllMacTemplate.match(NodeMAC):
                    if not 'mac' in json158Dict[jsonIndex]['network']:
                        print('++ No MAC in Alfred-158:',jsonIndex,'=',NodeMAC)
                    elif json158Dict[jsonIndex]['network']['mac'].strip().lower() != NodeMAC:
                        print('++ MAC Mismatch:',jsonIndex,'->',NodeMAC,'<>',json158Dict[jsonIndex]['network']['mac'].strip())

                    if NodeMAC not in self.ffNodeDict:
                        self.ffNodeDict[NodeMAC] = {
                            'RawKey': None,
                            'Name': json158Dict[jsonIndex]['hostname'],
                            'Status': ' ',
                            'last_online': HttpDate,
                            'Clients': 0,
                            'Latitude': None,
                            'Longitude': None,
                            'ZIP': None,
                            'Region': '??',
                            'DestSeg': None,
                            'GluonType': NODETYPE_UNKNOWN,
                            'MeshMACs':[],
                            'IPv6': None,
                            'Segment': None,
                            'SegMode': 'auto',
                            'KeyDir': '',
                            'KeyFile': '',
                            'FastdKey':'',
                            'InCloud': None,
                            'Neighbours': [],
                            'Owner': None
                        }

                        self.MAC2NodeIDDict[NodeMAC] = NodeMAC
                        print('++ Node added:    ',NodeMAC,'= \''+json158Dict[jsonIndex]['hostname']+'\'')

                    elif HttpDate > self.ffNodeDict[NodeMAC]['last_online']:
                        self.ffNodeDict[NodeMAC]['last_online'] = HttpDate

                    #---------- updating Node Infos ----------
                    if self.ffNodeDict[NodeMAC]['Name'] != json158Dict[jsonIndex]['hostname']:
                        print('++ Hostname mismatch:',NodeMAC,'= \''+json158Dict[jsonIndex]['hostname']+'\' -> \''+self.ffNodeDict[NodeMAC]['Name']+'\'')
                        self.ffNodeDict[NodeMAC]['Name'] = json158Dict[jsonIndex]['hostname']

                    if self.ffNodeDict[NodeMAC]['Status'] not in OnlineStates:
                        self.ffNodeDict[NodeMAC]['Status'] = ' '
#                        print('++ Node is online:',NodeMAC,'= \''+json158Dict[jsonIndex]['hostname']+'\'')

                    if 'addresses' in json158Dict[jsonIndex]['network']:
                        for NodeAddress in json158Dict[jsonIndex]['network']['addresses']:
                            if ffsIPv6Template.match(NodeAddress):
                                self.ffNodeDict[NodeMAC]['IPv6'] = NodeAddress

                                if NodeAddress[12:14] == '1e':
                                    self.ffNodeDict[NodeMAC]['Segment'] = 0
                                else:
                                    self.ffNodeDict[NodeMAC]['Segment'] = int(NodeAddress[12:14])

                    if 'mesh' in json158Dict[jsonIndex]['network']:
                        if 'bat0' in json158Dict[jsonIndex]['network']['mesh']:
                            if 'interfaces' in json158Dict[jsonIndex]['network']['mesh']['bat0']:
                                for InterfaceType in json158Dict[jsonIndex]['network']['mesh']['bat0']['interfaces']:
                                    if InterfaceType in ['tunnel','wireless','other']:
                                        for MeshMAC in json158Dict[jsonIndex]['network']['mesh']['bat0']['interfaces'][InterfaceType]:
                                            self.__AddGluonMACs(NodeMAC,MeshMAC)

                    if 'location' in json158Dict[jsonIndex]:
                        if 'latitude' in json158Dict[jsonIndex]['location'] and 'longitude' in json158Dict[jsonIndex]['location']:
                            self.ffNodeDict[NodeMAC]['Latitude']  = json158Dict[jsonIndex]['location']['latitude']
                            self.ffNodeDict[NodeMAC]['Longitude'] = json158Dict[jsonIndex]['location']['longitude']

                        if 'zip' in json158Dict[jsonIndex]['location']:
                            self.ffNodeDict[NodeMAC]['ZIP'] = str(json158Dict[jsonIndex]['location']['zip'])[:5]

                    self.__SetSegmentAwareness(NodeMAC,json158Dict[jsonIndex]['software'])

                else:
                    print('++ Gateway found:',NodeMAC)

        print('... done.\n')
        return



    #-------------------------------------------------------------
    # Load and analyse alfred-json-159.json
    #
    # Update self.ffNodeDict:
    #
    #   __ffNodeDict[NodeItem]['Status'] -> Node with VPN-Uplink?
    #-------------------------------------------------------------
    def __LoadAlfred159Json(self):

        print('Loading alfred-json-159.json ...')
        json159Dict = None
        Retries = 3

        while json159Dict is None and Retries > 0:
            Retries -= 1

            try:
                Afred159HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred159Name,timeout=10)
                HttpDate = int(calendar.timegm(time.strptime(Afred159HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = int(time.time()) - HttpDate

                print('>>> Age =',StatusAge,'Sec.')

                if StatusAge > MaxStatusAge:
                    Afred159HTTP.close()
                    self.__alert('++ alfred-json-159.json is too old !!!\n')
                    self.AnalyseOnly = True
                    return

                json159Dict = json.loads(Afred159HTTP.read().decode('utf-8'))
                Afred159HTTP.close()
            except:
                print('** need retry ...')
                json159Dict = None
                time.sleep(2)

        if json159Dict is None:
            self.__alert('++ Error on loading alfred-json-159.json !!!\n')
            self.AnalyseOnly = True
            return

        print('Analysing alfred-json-159.json ...',len(json159Dict))

        for jsonIndex in json159Dict:
            NodeID = json159Dict[jsonIndex]['node_id'].strip().lower()
            NodeMAC = NodeID[0:2] + ':' + NodeID[2:4] + ':' + NodeID[4:6] + ':' + NodeID[6:8] + ':' + NodeID[8:10] + ':' + NodeID[10:12]

            if not GwAllMacTemplate.match(NodeMAC):
                if not MacAdrTemplate.match(NodeMAC):
                    print('++ ERROR 159 NodeItem Format:',NodeMAC)

                elif NodeMAC not in self.ffNodeDict:
                    print('+++ Not in self.ffNodeDict:',NodeMAC)

                else:
                    if self.ffNodeDict[NodeMAC]['Status'] not in OnlineStates:
                        self.ffNodeDict[NodeMAC]['Status'] = ' '

                    if 'mesh_vpn' in json159Dict[jsonIndex]:
                        if 'groups' in json159Dict[jsonIndex]['mesh_vpn']:
                            if 'backbone' in json159Dict[jsonIndex]['mesh_vpn']['groups']:
                                if 'peers' in json159Dict[jsonIndex]['mesh_vpn']['groups']['backbone']:
                                    GWpeers = json159Dict[jsonIndex]['mesh_vpn']['groups']['backbone']['peers']

                                    for Uplink in GWpeers:
                                        if GWpeers[Uplink] is not None:
                                            if 'established' in GWpeers[Uplink]:
                                                self.ffNodeDict[NodeMAC]['Status'] = 'V'

                    if 'clients' in json159Dict[jsonIndex]:
                        if 'total' in json159Dict[jsonIndex]['clients']:
                            self.ffNodeDict[NodeMAC]['Clients'] = int(json159Dict[jsonIndex]['clients']['total'])

        print('... done.\n')
        return



    #-------------------------------------------------------------
    # private function "__LoadAlfred160Json"
    #
    #     Load and analyse alfred-json-160.json
    #
    #-------------------------------------------------------------
    def __LoadAlfred160Json(self):

        print('Loading alfred-json-160.json ...')
        json160Dict = None
        Retries = 3

        while json160Dict is None and Retries > 0:
            Retries -= 1

            try:
                Afred160HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred160Name,timeout=10)
                HttpDate = int(calendar.timegm(time.strptime(Afred160HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = int(time.time()) - HttpDate

                print('>>> Age =',StatusAge,'Sec.')

                if StatusAge > MaxStatusAge:
                    Afred160HTTP.close()
                    self.__alert('++ alfred-json-160.json is too old !!!\n')
                    self.AnalyseOnly = True
                    return

                json160Dict = json.loads(Afred160HTTP.read().decode('utf-8'))
                Afred160HTTP.close()
            except:
                print('** need retry ...')
                json160Dict = None
                time.sleep(2)

        if json160Dict is None:
            self.__alert('++ Error on loading alfred-json-160.json !!!\n')
            self.AnalyseOnly = True
            return

        print('Analysing alfred-json-160.json ...',len(json160Dict))

        for NodeItem in json160Dict:
            ffNodeID = json160Dict[NodeItem]['node_id'].strip().lower()
            ffNodeMAC = ffNodeID[0:2] + ':' + ffNodeID[2:4] + ':' + ffNodeID[4:6] + ':' + ffNodeID[6:8] + ':' + ffNodeID[8:10] + ':' + ffNodeID[10:22]

            if ffNodeMAC in self.ffNodeDict:
                if self.ffNodeDict[ffNodeMAC]['Status'] not in OnlineStates:
                    self.ffNodeDict[ffNodeMAC]['Status'] = ' '

                for MeshIF in ['batadv','wifi']:
                    if MeshIF in json160Dict[NodeItem]:
                        for batXX in json160Dict[NodeItem][MeshIF]:
                            if batXX not in self.MAC2NodeIDDict:
                                print('++ batXX missing:',batXX)
                                self.MAC2NodeIDDict[batXX] = ffNodeMAC

                            if 'neighbours' in json160Dict[NodeItem][MeshIF][batXX]:
                                for ffNeighbour in json160Dict[NodeItem][MeshIF][batXX]['neighbours']:
                                    if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                        (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                        self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

            else:
                print('++ Node unknown:',ffNodeMAC)

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__LoadRawJson"
    #
    #   Load and analyse raw.json
    #
    # RawJsonDict <- raw.json
    #
    # self.ffNodeDict[ffNodeMAC] -> all Infos of ffNode
    # self.MAC2NodeIDDict[ffNode] -> Main MAC
    #-----------------------------------------------------------------------
    def __LoadRawJson(self):

        print('Loading raw.json ...')
        RawJsonDict = None
        Retries = 5

        while RawJsonDict is None and Retries > 0:
            Retries -= 1

            try:
                passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                passman.add_password(None, self.__RawAccess['URL'], self.__RawAccess['Username'], self.__RawAccess['Password'])
                authhandler = urllib.request.HTTPBasicAuthHandler(passman)
                opener = urllib.request.build_opener(authhandler)
                urllib.request.install_opener(opener)

                RawJsonHTTP = urllib.request.urlopen(self.__RawAccess['URL'],timeout=15)
                print('... is open ...')
                RawJsonDict = json.loads(RawJsonHTTP.read().decode('utf-8'))
                RawJsonHTTP.close()
            except:
                print('** need retry ...')
                RawJsonDict = None
                time.sleep(2)

        if RawJsonDict is None:
            self.__alert('++ Error on loading raw.json !!!\n')
#            self.AnalyseOnly = True
            return

        print('Analysing raw.json ...')

        UnixTime = int(time.time())
        NewestTime = 0
        NodeCount = 0

        for ffNodeKey in RawJsonDict.keys():
            if 'nodeinfo' in RawJsonDict[ffNodeKey] and 'statistics' in RawJsonDict[ffNodeKey] and 'lastseen' in RawJsonDict[ffNodeKey]:

                if RawJsonDict[ffNodeKey]['nodeinfo']['node_id'] != ffNodeKey or RawJsonDict[ffNodeKey]['statistics']['node_id'] != ffNodeKey:
                    print('++ NodeID-Mismatch:',RawJsonDict[ffNodeKey]['nodeinfo']['node_id'],ffNodeKey)
                    continue

                ffNodeMAC = RawJsonDict[ffNodeKey]['nodeinfo']['network']['mac'].strip().lower()

                if not MacAdrTemplate.match(ffNodeMAC):
                    print('!! Invalid MAC Format:',ffNodeKey,ffNodeMAC)
                    continue

                ffNodeID = ffNodeMAC.replace(':','')

                if ffNodeID != ffNodeKey[:12].lower():
                    print('++ NodeID-MAC-Mismatch:',ffNodeKey,'<->',ffNodeID,'=',ffNodeMAC)
                    continue

                if not GwAllMacTemplate.match(ffNodeMAC):
                    if (('software' not in RawJsonDict[ffNodeKey]['nodeinfo']) or
                          ('firmware' not in RawJsonDict[ffNodeKey]['nodeinfo']['software']) or
                          ('release' not in RawJsonDict[ffNodeKey]['nodeinfo']['software']['firmware']) or
                          (RawJsonDict[ffNodeKey]['nodeinfo']['software']['firmware']['release'] is None) or
                          ('hostname' not in RawJsonDict[ffNodeKey]['nodeinfo']) or
                          ('network' not in RawJsonDict[ffNodeKey]['nodeinfo'])):
                        print('++ Invalid Record:',ffNodeKey,'=',ffNodeMAC)
                        continue

                    LastSeen = int(calendar.timegm(time.strptime(RawJsonDict[ffNodeKey]['lastseen'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    if LastSeen > NewestTime:
                        NewestTime = LastSeen

                    if ffNodeMAC in self.ffNodeDict:
                        if self.ffNodeDict[ffNodeMAC]['RawKey'] is None:
                            self.ffNodeDict[ffNodeMAC]['RawKey'] = ffNodeKey
                        else:
                            if self.ffNodeDict[ffNodeMAC]['last_online'] > LastSeen:
                                continue    # newer Duplicate already in raw.json
                            else:
                                print('-+ Upd. RAW:',ffNodeKey,'=',ffNodeMAC,'= \''+RawJsonDict[ffNodeKey]['nodeinfo']['hostname']+'\'')
                                self.ffNodeDict[ffNodeMAC]['RawKey'] = ffNodeKey

                    else:
                        print('++ New Node:',ffNodeKey,'=',ffNodeMAC,'= \''+RawJsonDict[ffNodeKey]['nodeinfo']['hostname']+'\'')
                        self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC

                        self.ffNodeDict[ffNodeMAC] = {
                            'RawKey': ffNodeKey,
                            'Name': RawJsonDict[ffNodeKey]['nodeinfo']['hostname'],
                            'Status': '#',
                            'last_online': 0,
                            'Clients': 0,
                            'Latitude': None,
                            'Longitude': None,
                            'ZIP': None,
                            'Region': '??',
                            'DestSeg': None,
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


                    if LastSeen > self.ffNodeDict[ffNodeMAC]['last_online']:
                        self.ffNodeDict[ffNodeMAC]['last_online'] = LastSeen
                        self.ffNodeDict[ffNodeMAC]['Clients'] = 0

                        if 'clients' in RawJsonDict[ffNodeKey]['statistics']:
                            if RawJsonDict[ffNodeKey]['statistics']['clients'] is not None:
                                if 'total' in RawJsonDict[ffNodeKey]['statistics']['clients']:
                                    self.ffNodeDict[ffNodeMAC]['Clients'] = int(RawJsonDict[ffNodeKey]['statistics']['clients']['total'])
                                else:
                                    print('!!! total statistics missing:',ffNodeKey)

                        if self.ffNodeDict[ffNodeMAC]['Name'] != RawJsonDict[ffNodeKey]['nodeinfo']['hostname']:
                            print('++ Hostname mismatch:',ffNodeMAC,'=',self.ffNodeDict[ffNodeMAC]['Name']+'\' -> \''+RawJsonDict[ffNodeKey]['nodeinfo']['hostname']+'\'')
                            self.ffNodeDict[ffNodeMAC]['Name'] = RawJsonDict[ffNodeKey]['nodeinfo']['hostname']

                        if 'location' in RawJsonDict[ffNodeKey]['nodeinfo']:
                            if 'latitude' in RawJsonDict[ffNodeKey]['nodeinfo']['location'] and 'longitude' in RawJsonDict[ffNodeKey]['nodeinfo']['location']:
                                self.ffNodeDict[ffNodeMAC]['Latitude']  = RawJsonDict[ffNodeKey]['nodeinfo']['location']['latitude']
                                self.ffNodeDict[ffNodeMAC]['Longitude'] = RawJsonDict[ffNodeKey]['nodeinfo']['location']['longitude']

                            if 'zip' in RawJsonDict[ffNodeKey]['nodeinfo']['location']:
                                self.ffNodeDict[ffNodeMAC]['ZIP'] = str(RawJsonDict[ffNodeKey]['nodeinfo']['location']['zip'])[:5]

                        if 'owner' in RawJsonDict[ffNodeKey]['nodeinfo']:
                            if 'contact' in RawJsonDict[ffNodeKey]['nodeinfo']['owner']:
                                self.ffNodeDict[ffNodeMAC]['Owner'] = RawJsonDict[ffNodeKey]['nodeinfo']['owner']['contact']

                        if 'mesh' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                            for InterfaceType in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh']['bat0']['interfaces']:
                                for MeshMAC in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh']['bat0']['interfaces'][InterfaceType]:
                                    if self.__AddGluonMACs(ffNodeMAC,MeshMAC) is not None:
                                        LastSeen = 0
                                        break

                        elif 'mesh_interfaces' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                            for MeshMAC in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh_interfaces']:
                                if self.__AddGluonMACs(ffNodeMAC,MeshMAC) is not None:
                                    LastSeen = 0
                                    break

                    if UnixTime - LastSeen < MaxOfflineTime:
                        NodeCount += 1

                        if self.ffNodeDict[ffNodeMAC]['Status'] not in OnlineStates:
                            self.ffNodeDict[ffNodeMAC]['Status'] = ' '   # -> online
#                            print('>>> Node is online:',ffNodeKey,'=',ffNodeMAC,'= \''+RawJsonDict[ffNodeKey]['nodeinfo']['hostname']+'\'')

                        if 'neighbours' in RawJsonDict[ffNodeKey]:
                            for InterfaceType in ['batadv','wifi']:
                                if InterfaceType in RawJsonDict[ffNodeKey]['neighbours']:
                                    for MeshMAC in RawJsonDict[ffNodeKey]['neighbours'][InterfaceType]:

                                        if 'neighbours' in RawJsonDict[ffNodeKey]['neighbours'][InterfaceType][MeshMAC]:
                                            for ffNeighbour in RawJsonDict[ffNodeKey]['neighbours'][InterfaceType][MeshMAC]['neighbours']:
                                                if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                                    (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                                    self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

                        if 'addresses' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                            for NodeAddress in RawJsonDict[ffNodeKey]['nodeinfo']['network']['addresses']:
                                if ffsIPv6Template.match(NodeAddress):
                                    self.ffNodeDict[ffNodeMAC]['IPv6'] = NodeAddress

                                    if NodeAddress[12:14] == '1e':
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = 0
                                    else:
                                        self.ffNodeDict[ffNodeMAC]['Segment'] = int(NodeAddress[12:14])

                        if 'gateway' in RawJsonDict[ffNodeKey]['statistics']:
                            if RawJsonDict[ffNodeKey]['statistics']['gateway'][:9] == '02:00:0a:':
                                self.ffNodeDict[ffNodeMAC]['Segment'] = int(RawJsonDict[ffNodeKey]['statistics']['gateway'][12:14])
                            elif GwNewMacTemplate.match(RawJsonDict[ffNodeKey]['statistics']['gateway']):
                                self.ffNodeDict[ffNodeMAC]['Segment'] = int(RawJsonDict[ffNodeKey]['statistics']['gateway'][9:11])

                        if 'mesh_vpn' in RawJsonDict[ffNodeKey]['statistics']:
                            if 'groups' in RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']:
                                if 'backbone' in RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']['groups']:
                                    if 'peers' in RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']['groups']['backbone']:
                                        GWpeers = RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']['groups']['backbone']['peers']

                                        for Uplink in GWpeers:
                                            if GWpeers[Uplink] is not None:
                                                if 'established' in GWpeers[Uplink]:
                                                    self.ffNodeDict[ffNodeMAC]['Status'] = 'V'

                    elif UnixTime - LastSeen > MaxInactiveTime:
#                        print('>>> Old RAW:',ffNodeKey,'=',ffNodeMAC,'= \''+RawJsonDict[ffNodeKey]['nodeinfo']['hostname']+'\''))
                        self.ffNodeDict[ffNodeMAC]['Status'] = '?'   # -> inactive

                    self.__SetSegmentAwareness(ffNodeMAC,RawJsonDict[ffNodeKey]['nodeinfo']['software'])

            else:
                print('** Invalid Record:',ffNodeKey)

        print('... %d Nodes done, Age = %d sec.\n' % (NodeCount,UnixTime-NewestTime))

        if (NodeCount > 1000) and ((UnixTime-NewestTime) < 60):
            self.AnalyseOnly = False

        return



    #-------------------------------------------------------------
    # private function "__CheckNodeHostnames"
    #
    #     Checking Hostnames of Nodes
    #
    #-------------------------------------------------------------
    def __CheckNodeHostnames(self):

        print('Checking Hostnames of Nodes ...')

        for ffNodeMAC in self.ffNodeDict:
            if BadNameTemplate.match(self.ffNodeDict[ffNodeMAC]['Name']):
                print('!! Invalid ffNode Hostname:',self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'->','\''+self.ffNodeDict[ffNodeMAC]['Name']+'\'')

        print('... done.\n')
        return



    #=========================================================================
    # Method "AddNode"
    #
    #   Adds a Node { 'SegDir','SegMode','VpnMAC','PeerMAC','PeerName','PeerKey' }
    #
    #=========================================================================
    def AddNode(self,KeyIndex,FastdKeyInfo):

        newNode = False
        ffNodeMAC = FastdKeyInfo['PeerMAC']

        if not MacAdrTemplate.match(ffNodeMAC):
            print('!! Bad PeerMAC:',ffNodeMAC)

        else:
            if not ffNodeMAC in self.ffNodeDict:

                self.ffNodeDict[ffNodeMAC] = {
                    'RawKey': None,
                    'Name': FastdKeyInfo['PeerName'],
                    'Status': '?',
                    'last_online': 0,
                    'Clients': 0,
                    'Latitude': None,
                    'Longitude': None,
                    'ZIP': None,
                    'Region': '??',
                    'DestSeg': None,
                    'GluonType': NODETYPE_LEGACY,
                    'MeshMACs':[],
                    'IPv6': None,
                    'Segment': int(FastdKeyInfo['SegDir'][3:]),
                    'SegMode': FastdKeyInfo['SegMode'],
                    'KeyDir': FastdKeyInfo['SegDir'],
                    'KeyFile': KeyIndex,
                    'FastdKey': FastdKeyInfo['PeerKey'],
                    'InCloud': None,
                    'Neighbours': [],
                    'Owner': None
                }

                self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC
                newNode = True

                if FastdKeyInfo['VpnMAC'] != '':
                    print('!! New VPN-Node:  ',FastdKeyInfo['SegDir'],'/',ffNodeMAC,'= \''+FastdKeyInfo['PeerName']+'\'')
                    self.__AddGluonMACs(ffNodeMAC,FastdKeyInfo['VpnMAC'])

                    if FastdKeyInfo['SegDir'] > 'vpn08':
                        self.ffNodeDict[ffNodeMAC]['GluonType'] = NODETYPE_DNS_SEGASSIGN
                    elif FastdKeyInfo['SegDir'] > 'vpn00':
                        self.ffNodeDict[ffNodeMAC]['GluonType'] = NODETYPE_SEGMENT_LIST
#                else:
#                    print('++ New Node:    ',FastdKeyInfo['SegDir'],'/',ffNodeMAC,'= \''+FastdKeyInfo['PeerName']+'\'')

            else:   # updating existing node
                self.ffNodeDict[ffNodeMAC]['SegMode']  = FastdKeyInfo['SegMode']
                self.ffNodeDict[ffNodeMAC]['KeyDir']   = FastdKeyInfo['SegDir']
                self.ffNodeDict[ffNodeMAC]['KeyFile']  = KeyIndex
                self.ffNodeDict[ffNodeMAC]['FastdKey'] = FastdKeyInfo['PeerKey']

            if FastdKeyInfo['VpnMAC'] != '':
                if self.ffNodeDict[ffNodeMAC]['Status'] == '?':
                    print('!! Node is alive: ',FastdKeyInfo['SegDir'],'/',FastdKeyInfo['VpnMAC'],'->',ffNodeMAC,'= \''+FastdKeyInfo['PeerName']+'\'')
                elif self.ffNodeDict[ffNodeMAC]['Status'] != 'V':
                    print('++ Node is online:',FastdKeyInfo['SegDir'],'/',FastdKeyInfo['VpnMAC'],'->',ffNodeMAC,'= \''+FastdKeyInfo['PeerName']+'\'')

                self.ffNodeDict[ffNodeMAC]['Segment'] = int(FastdKeyInfo['SegDir'][3:])
                self.ffNodeDict[ffNodeMAC]['Status'] = 'V'

                if FastdKeyInfo['LastConn'] > self.ffNodeDict[ffNodeMAC]['last_online']:
                    self.ffNodeDict[ffNodeMAC]['last_online'] = FastdKeyInfo['LastConn']

        return newNode



    #==============================================================================
    # Method "IsOnline"
    #
    #   True = Node is Online
    #==============================================================================
    def IsOnline(self,ffNodeMAC):

        if not ffNodeMAC in self.ffNodeDict:
            return False

        return (self.ffNodeDict[ffNodeMAC]['Status'] in OnlineStates)



    #==============================================================================
    # Method "GetBatmanNodeMACs"
    #
    #   Verify Tunnel-MAC / Main-MAC with batman Debug Tables TG and O
    #
    #==============================================================================
    def GetBatmanNodeMACs(self,SegmentList):

        print('\nAnalysing Batman Tables ...')
        UnixTime = int(time.time())
        TotalNodes = 0
        TotalClients = 0

        for ffSeg in SegmentList:
            print('... Segment',ffSeg,'...')
            BatmanIF  = 'bat%02d' % (ffSeg)
            NodeCount = 0
            ClientCount = 0

            try:
                with open(os.path.join(BATMAN_DEBUG_FILES,BatmanIF,BATMAN_TRANS_TABLE), mode='r') as TransTableFile:
                    BatmanTransTable = TransTableFile.read().splitlines()
            except:
                print('!! ERROR on Batman Translation Table of',BatmanIF)
                BatmanTransTable = None
            else:
                for TransItem in BatmanTransTable:
                    BatctlInfo = TransItem.replace('(',' ').replace(')',' ').split()

                    if len(BatctlInfo) == 9 and MacAdrTemplate.match(BatctlInfo[1]) and not GwAllMacTemplate.match(BatctlInfo[1]):
                        ffNodeMAC = BatctlInfo[1]
                        ffMeshMAC = BatctlInfo[5]

                        if BatctlInfo[2] == '-1' and MacAdrTemplate.match(ffMeshMAC) and not GwAllMacTemplate.match(ffMeshMAC):

                            if ffMeshMAC[:1] == ffNodeMAC[:1] and ffMeshMAC[9:] == ffNodeMAC[9:]:  # old Gluon MAC schema
                                BatmanMacList = self.GenerateGluonMACsOld(ffNodeMAC)
                            else:  # new Gluon MAC schema
                                BatmanMacList = self.GenerateGluonMACsNew(ffNodeMAC)

                            if ffMeshMAC in BatmanMacList:  # Data is from Node
                                NodeCount += 1

                                if ffNodeMAC in self.ffNodeDict:
                                    if ffMeshMAC in self.MAC2NodeIDDict and self.MAC2NodeIDDict[ffMeshMAC] != ffNodeMAC:
                                        print('!! MAC mismatch Tunnel -> Client: Batman <> Alfred:',ffMeshMAC,'->',ffNodeMAC,'<>',self.MAC2NodeIDDict[ffMeshMAC])

                                    self.ffNodeDict[ffNodeMAC]['Segment'] = ffSeg
                                    self.__AddGluonMACs(ffNodeMAC,ffMeshMAC)
                                    self.ffNodeDict[ffNodeMAC]['last_online'] = UnixTime

                                    if self.ffNodeDict[ffNodeMAC]['Status'] not in OnlineStates:
                                        self.ffNodeDict[ffNodeMAC]['Status'] = ' '
                                        print('    >> Node is online:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\'')
                                else:
                                    print('++ New Node in Batman:',ffSeg,'/',ffNodeMAC)

                            else:  # Data is from Client
                                ClientCount += 1

            print('... Nodes / Clients:',NodeCount,'/',ClientCount)
            TotalNodes   += NodeCount
            TotalClients += ClientCount


            try:
                with open(os.path.join(BATMAN_DEBUG_FILES,BatmanIF,BATMAN_ORIGI_TABLE), mode='r') as OriginTableFile:
                    BatmanOriginTable = OriginTableFile.read().splitlines()
            except:
                print('!! ERROR on Batman Originator Table of',BatmanIF)
            else:
                for OriginItem in BatmanOriginTable:
                    BatctlInfo = OriginItem.split()

                    if len(BatctlInfo) > 5 and MacAdrTemplate.match(BatctlInfo[0]) and not GwAllMacTemplate.match(BatctlInfo[0]):
                        if BatctlInfo[0] not in self.MAC2NodeIDDict:
                            print('++ Unknown Node in Batman Originator Table:',ffSeg,'/',BatctlInfo[0])


        print('\nTotalNodes / TotalClients =',TotalNodes,'/',TotalClients)
        print('... done.\n')
        return



    #==============================================================================
    # Method "GetUplinkList"
    #
    #   returns UplinkList from NodeList verified by batman traceroute
    #
    #==============================================================================
    def GetUplinkList(self,NodeList,SegmentList):

        print('... Analysing Batman Traceroute:',NodeList,'->',SegmentList,'...')
        UplinkList = []

        for ffNodeMAC in NodeList:
            for ffSeg in SegmentList:
                BatctlCmd = ('/usr/sbin/batctl -m bat%02d tr %s' % (ffSeg,ffNodeMAC)).split()

                try:
                    BatctlTr = subprocess.run(BatctlCmd, stdout=subprocess.PIPE)
                    BatctlResult = BatctlTr.stdout.decode('utf-8')
                except:
                    print('++ ERROR accessing batman:',BatctlCmd)
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
                                        self.ffNodeDict[ffNodeMAC]['Status'] = 'V'
                                    break

        if len(UplinkList) < 1:
            UplinkList = None

        return UplinkList



    #==============================================================================
    # Method "DumpMacTable"
    #
    #   Dump out MAC-Table
    #==============================================================================
    def DumpMacTable(self,FileName):

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

        print('... ZIP-Codes loaded:',ZipCount,'\n')
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
            print('!! ERROR on registering ZIP-Areas:',len(ZipFileDict),'\n')
            ZipFileDict = None
        else:
            print('... ZIP-Areas registered:',len(ZipFileDict),'\n')

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

        print('... ZIP-Fields loaded:',FieldCount,'\n')
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
                    print('!! Missing Region Polygon:',Region)

        print('... Region Areas loaded:',RegionCount,'\n')
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

                for Region in RegionDict['Polygons'].keys():
                    if Region not in RegionDict['WithZip']:
                        MatchCount = 0

                        for RegionPart in RegionDict['Polygons'][Region]:
                            if RegionPart.intersects(NodeLocation):
                                MatchCount += 1

                        if MatchCount == 1:
                            GpsRegion = Region
                            break

            else:
                print('!! Invalid Location:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',lon,'|',lat)

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
            for ffNodeMAC in self.ffNodeDict.keys():
                if self.ffNodeDict[ffNodeMAC]['Status'] == '?': continue

                if self.ffNodeDict[ffNodeMAC]['GluonType'] >= NODETYPE_SEGMENT_LIST:  # Segment aware Gluon
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
                        print('>>> ZIP-Code Mismatch GPS <> ZIP:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',GpsZipCode,'<>',ZipCode)
                        self.ffNodeDict[ffNodeMAC]['ZIP'] = GpsZipCode

                    if GpsRegion is not None:
                        self.ffNodeDict[ffNodeMAC]['Region']  = GpsRegion
                        self.ffNodeDict[ffNodeMAC]['DestSeg'] = GpsSegment

                        if GpsSegment > 8 and self.ffNodeDict[ffNodeMAC]['GluonType'] < NODETYPE_DNS_SEGASSIGN:
                            print('!! Invalid Segment for Gluon-Version:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',GpsSegment)

                    if self.ffNodeDict[ffNodeMAC]['SegMode'][:4] == 'fix ':
                        GpsSegment = int(self.ffNodeDict[ffNodeMAC]['SegMode'][4:])
                        self.ffNodeDict[ffNodeMAC]['DestSeg'] = GpsSegment
#                        print('+++ Segment is fix:',ffNodeMAC,'= \''+self.ffNodeDict[ffNodeMAC]['Name']+'\' ->',GpsSegment)

                else:  # old Gluon without Segment Support
                    self.ffNodeDict[ffNodeMAC]['DestSeg'] = 0

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

            for ffNodeMAC in self.ffNodeDict.keys():
                if self.ffNodeDict[ffNodeMAC]['IPv6'] is not None:
                    DnsNodeID = 'ffs-' + ffNodeMAC.replace(':','')

                    if DnsNodeID in NodeDnsDict:
                        if NodeDnsDict[DnsNodeID] != self.ffNodeDict[ffNodeMAC]['IPv6']:
                            DnsUpdate.replace(DnsNodeID, 120, 'AAAA',self.ffNodeDict[ffNodeMAC]['IPv6'])
                    else:
                        DnsUpdate.add(DnsNodeID, 120, 'AAAA',self.ffNodeDict[ffNodeMAC]['IPv6'])

            if len(DnsUpdate.index) > 1:
                dns.query.tcp(DnsUpdate,DnsServerIP)

        print('... done.\n')
        return
