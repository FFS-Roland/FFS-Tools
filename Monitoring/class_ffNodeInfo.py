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
#       raw.json                  -> Node Names and Information                           #
#       nodesdb.json              -> Region = Segment                                     #
#       alfred-json-158.json      -> Nodeinfos                                            #
#       alfred-json-159.json      -> VPN-Uplinks                                          #
#       alfred-json-160.json      -> Neighbors                                            #
#                                                                                         #
#       regions/<segment>/*.json  -> Polygons of Regions                                  #
#       regions/ZIP2GPS_DE.json   -> Dict. of ZIP-Codes with related GPS-Positions        #
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
import subprocess
import urllib.request
import time
import datetime
import json
import re
import hashlib
import overpy

from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
from glob import glob


#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

MaxInactiveTime    = 10 * 86400     # 10 Days (in Seconds)
MaxOfflineTime     = 30 * 60        # 30 Minutes (in Seconds)

OnlineStates       = [' ','V']      # online, online with VPN-Uplink


NodesDbName    = 'nodesdb.json'
Alfred158Name  = 'alfred-json-158.json'
Alfred159Name  = 'alfred-json-159.json'
Alfred160Name  = 'alfred-json-160.json'

ZipTableName   = 'ZIP2GPS_DE.json'  # Data merged from OpenStreetMap and OpenGeoDB


GwNameTemplate    = re.compile('^gw[01][0-9]{1,2}')
GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[5-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate  = re.compile('^02:00:(3[5-9])(:[0-9a-f]{2}){3}')

MacAdrTemplate    = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
NodeIdTemplate    = re.compile('^[0-9a-f]{12}$')

PeerTemplate      = re.compile('^ffs-[0-9a-f]{12}')
PeerTemplate1     = re.compile('^ffs[-_][0-9a-f]{12}')
PeerTemplate2     = re.compile('^ffs[0-9a-f]{12}')

ZipTemplate       = re.compile('^[0-9]{5}$')
SegmentTemplate   = re.compile('^[0-9]{2}$')

KeyDirTemplate    = re.compile('^vpn[0-9]{2}$')
FastdKeyTemplate  = re.compile('^[0-9a-f]{64}$')


GoodOldGluonList  = [
    '0.6-g.271e864',
#    '0.6-g.88bdc98',
    '0.6-g.df018ed',
    '0.7-g.97879e8'
]




class ffNodeInfo:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,AlfredURL,RawAccess):

        # public Attributes
        self.MAC2NodeIDDict  = {}       # Dictionary of all Nodes' MAC-Addresses and related Main Address
        self.ffNodeDict      = {}       # Dictionary of Nodes [MainMAC] with their Name, VPN-Uplink
        self.Alerts          = []       # List of  Alert-Messages
        self.AnalyseOnly     = False    # Locking automatic Actions due to inconsistent Data

        # private Attributes
        self.__AlfredURL = AlfredURL
        self.__RawAccess = RawAccess

        # Initializations
        self.__LoadNodesDbJson()        # ffNodeDict[ffNodeMAC] -> all Alfred-Infos of ffNode
        self.__LoadAlfred158Json()      # verify Infos of Nodes
        self.__LoadAlfred159Json()      # check for VPN-Uplinks of Nodes
        self.__LoadAlfred160Json()      # get the Neighbours of the Nodes

        self.__LoadRawJson()            # add or update Info with Data from announced / respondd

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
    # -- (3, n): adhoc interface for n'th radio
    # -- (4, 0): mesh VPN
    # -- (5, n): mesh interface for n'th radio (802.11s)
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
    # -- 0 + 8: client0; WAN
    # -- 1 + 9: mesh0
    # -- 2 + a: ibss0
    # -- 3 + b: wan_radio0 (private WLAN); batman-adv primary address
    # -- 4 + c: client1; LAN
    # -- 5 + d: mesh1
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

        if MeshMAC != '':
            GluonMacList = self.GenerateGluonMACsNew(MainMAC)

            if not MeshMAC in GluonMacList:
                GluonMacList = self.GenerateGluonMACsOld(MainMAC)

                if not MeshMAC in GluonMacList:
                    GluonMacList = [MeshMAC]

        else:   # only MainMAC available
            GluonMacList = self.GenerateGluonMACsNew(MainMAC)

            knownMAC = False

            for NewMAC in GluonMacList:
                if NewMAC in self.MAC2NodeIDDict:
                    knownMAC = True
                    break

            if not knownMAC:
                GluonMacList = self.GenerateGluonMACsOld(MainMAC)

                for NewMAC in GluonMacList:
                    if NewMAC in self.MAC2NodeIDDict:
                        knownMAC = True
                        break

            if knownMAC:
                GluonMacList = []

        for NewMAC in GluonMacList:
            if NewMAC in self.MAC2NodeIDDict:
                if self.MAC2NodeIDDict[NewMAC] != MainMAC:
                    print('\n!! MAC-Collision:',NewMAC)
                    print('        New Node:',self.ffNodeDict[MainMAC]['KeyDir'],'/',MainMAC,'=',self.ffNodeDict[MainMAC]['Name'].encode('utf-8'))
                    print('   Existing Node:',self.ffNodeDict[self.MAC2NodeIDDict[NewMAC]]['KeyDir'],'/',self.MAC2NodeIDDict[NewMAC],'=',self.ffNodeDict[self.MAC2NodeIDDict[NewMAC]]['Name'].encode('utf-8'))
                    print()

                    if not NewMAC in self.ffNodeDict[MainMAC]['Neighbours']:
                        self.ffNodeDict[MainMAC]['Neighbours'].append(NewMAC)
            else:
                self.MAC2NodeIDDict[NewMAC] = MainMAC

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

        try:
            NodesDbJsonHTTP = urllib.request.urlopen(self.__AlfredURL+NodesDbName,timeout=10)
            HttpDate = datetime.datetime.strptime(NodesDbJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate

            if StatusAge.total_seconds() > 900:
                NodesDbJsonHTTP.close()
                self.__alert('++ nodesdb.json is too old !!!')
                self.AnalyseOnly = True
                return

            jsonDbDict = json.loads(NodesDbJsonHTTP.read().decode('utf-8'))
            NodesDbJsonHTTP.close()
        except:
            self.__alert('Error on loading nodesdb.json !!!')
            self.AnalyseOnly = True
            return

        print('Analysing nodesdb.json ...')

        UnixTime = time.mktime(datetime.datetime.utcnow().timetuple())

        for DbIndex in jsonDbDict:
            NodeNets  = jsonDbDict[DbIndex]['network']
            ffNodeMAC = jsonDbDict[DbIndex]['network']['mac'].strip()

            if not GwAllMacTemplate.match(DbIndex) and not GwAllMacTemplate.match(ffNodeMAC):
                if not MacAdrTemplate.match(DbIndex) or not MacAdrTemplate.match(ffNodeMAC):
                    print('++ ERROR nodesdb.json ffNode Format:',DbIndex,'->',ffNodeMAC)
                else:
                    if ffNodeMAC in self.ffNodeDict:
                        print('++ Node already stored:',ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Status'],self.ffNodeDict[ffNodeMAC]['last_online'],'->',DbIndex,jsonDbDict[DbIndex]['status'],jsonDbDict[DbIndex]['last_online'])

                        if self.ffNodeDict[ffNodeMAC]['last_online'] > jsonDbDict[DbIndex]['last_online']:
                            # correct version alredy stored
                            continue

                    self.ffNodeDict[ffNodeMAC] = {
                        'RawKey':None,
                        'Name':jsonDbDict[DbIndex]['hostname'],
                        'Status':'#',
                        'last_online':jsonDbDict[DbIndex]['last_online'],
                        'Clients':0,
                        'Latitude':None,
                        'Longitude':None,
                        'ZIP':None,
                        'Region':'??',
                        'DestSeg':99,
                        'oldGluon':'?',
                        'Segment':None,
                        'SegMode':'auto',
                        'KeyDir':'',
                        'KeyFile':'',
                        'FastdKey':'',
                        'InCloud':0,
                        'Neighbours':[]
                    }

                    self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC

                    if UnixTime - jsonDbDict[DbIndex]['last_online'] > MaxInactiveTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = '?'
                    else:
                        if jsonDbDict[DbIndex]['last_online'] > NewestTime:
                            NewestTime = jsonDbDict[DbIndex]['last_online']

                        if jsonDbDict[DbIndex]['status'] == 'online' and (UnixTime - jsonDbDict[DbIndex]['last_online']) < MaxOfflineTime:
                            self.ffNodeDict[ffNodeMAC]['Status'] = ' '

                            if 'clients' in jsonDbDict[DbIndex]:
                                self.ffNodeDict[ffNodeMAC]['Clients'] = int(jsonDbDict[DbIndex]['clients']['total'])

                            if 'neighbours' in jsonDbDict[DbIndex]:
                                for ffNeighbour in jsonDbDict[DbIndex]['neighbours']:
                                    if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                        (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                        self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

                        if 'addresses' in NodeNets:
                            for NodeAddress in NodeNets['addresses']:
                                if NodeAddress[0:9] == 'fd21:711:' and 'status-page' in jsonDbDict[DbIndex]['software']:
                                    self.ffNodeDict[ffNodeMAC]['oldGluon'] = ' '

                    if 'segment' in jsonDbDict[DbIndex]:
                        self.ffNodeDict[ffNodeMAC]['Segment'] = int(jsonDbDict[DbIndex]['segment'])

                    if 'gateway' in jsonDbDict[DbIndex]:
                        if jsonDbDict[DbIndex]['gateway'][:9] == '02:00:0a:':
                            GwSeg = int(jsonDbDict[DbIndex]['gateway'][13:14])
                        elif GwNewMacTemplate.match(jsonDbDict[DbIndex]['gateway']):
                            GwSeg = int(jsonDbDict[DbIndex]['gateway'][10:11])
                        else:
                            GwSeg = None

                        if not GwSeg is None:
                            if self.ffNodeDict[ffNodeMAC]['Segment'] is None:
                                self.ffNodeDict[ffNodeMAC]['Segment'] = GwSeg
                            elif self.ffNodeDict[ffNodeMAC]['Segment'] != GwSeg:
                                print('!! Segment mismatch:',self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,self.ffNodeDict[ffNodeMAC]['Segment'],'<>',GwSeg,'=',self.ffNodeDict[ffNodeMAC]['Name'])

                    if 'location' in jsonDbDict[DbIndex]:
                        if 'latitude' in jsonDbDict[DbIndex]['location'] and 'longitude' in jsonDbDict[DbIndex]['location']:
                            self.ffNodeDict[ffNodeMAC]['Latitude']  = jsonDbDict[DbIndex]['location']['latitude']
                            self.ffNodeDict[ffNodeMAC]['Longitude'] = jsonDbDict[DbIndex]['location']['longitude']

                        if 'zip' in jsonDbDict[DbIndex]['location']:
                            self.ffNodeDict[ffNodeMAC]['ZIP'] = str(jsonDbDict[DbIndex]['location']['zip'])[:5]

                    if 'region' in jsonDbDict[DbIndex]:
                        self.ffNodeDict[ffNodeMAC]['Region'] = jsonDbDict[DbIndex]['region']

                    if 'desiredSegment' in jsonDbDict[DbIndex]:
                        if SegmentTemplate.match(jsonDbDict[DbIndex]['desiredSegment']):
                            self.ffNodeDict[ffNodeMAC]['DestSeg'] = int(jsonDbDict[DbIndex]['desiredSegment'])

                    if 'mesh_interfaces' in NodeNets:
                        for MeshMAC in NodeNets['mesh_interfaces']:
                            self.MAC2NodeIDDict[MeshMAC] = ffNodeMAC
                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                    if 'mesh' in NodeNets:
                        if 'bat0' in NodeNets['mesh']:
                            if 'interfaces' in NodeNets['mesh']['bat0']:
                                for InterfaceType in NodeNets['mesh']['bat0']['interfaces']:
                                    if InterfaceType in ['tunnel','wireless','other']:
                                        for MeshMAC in NodeNets['mesh']['bat0']['interfaces'][InterfaceType]:
                                            self.MAC2NodeIDDict[MeshMAC] = ffNodeMAC
                                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                    if 'software' in jsonDbDict[DbIndex]:
                        if 'firmware' in jsonDbDict[DbIndex]['software']:
                            self.ffNodeDict[ffNodeMAC]['oldGluon'] = '%'

                            if 'release' in jsonDbDict[DbIndex]['software']['firmware']:
                                if jsonDbDict[DbIndex]['software']['firmware']['release'] is not None:
                                    if jsonDbDict[DbIndex]['software']['firmware']['release'][:11] >= '0.7+2016.03':
                                        self.ffNodeDict[ffNodeMAC]['oldGluon'] = ' '
                                    elif jsonDbDict[DbIndex]['software']['firmware']['release'][:13] in GoodOldGluonList:
                                        self.ffNodeDict[ffNodeMAC]['oldGluon'] = ' '
                                    else:
                                        self.ffNodeDict[ffNodeMAC]['SegMode'] = 'fix vpn00'

                            if 'base' in jsonDbDict[DbIndex]['software']['firmware']:
                                if jsonDbDict[DbIndex]['software']['firmware']['base'] is not None:
                                    if jsonDbDict[DbIndex]['software']['firmware']['base'] == 'gluon-v2016.1.3' and 'status-page' in jsonDbDict[DbIndex]['software']:
                                        self.ffNodeDict[ffNodeMAC]['oldGluon'] = ' '

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

        try:
            Afred158HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred158Name,timeout=10)
            HttpDate = datetime.datetime.strptime(Afred158HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate

            JsonUnixTime = int(time.mktime(HttpDate.timetuple()))

            if StatusAge.total_seconds() > 900:
                Afred158HTTP.close()
                self.__alert('++ alfred-json-158.json is too old !!!')
                self.AnalyseOnly = True
                return

            json158Dict = json.loads(Afred158HTTP.read().decode('utf-8'))
            Afred158HTTP.close()
        except:
            self.__alert('++ Error on loading alfred-json-158.json !!!')
            self.AnalyseOnly = True
            return

        print('Analysing alfred-json-158.json ...')

        for jsonIndex in json158Dict:
            if ((not 'node_id' in json158Dict[jsonIndex]) or
                (not 'hostname' in json158Dict[jsonIndex]) or
                (not 'network' in json158Dict[jsonIndex]) or
                (not 'software' in json158Dict[jsonIndex])):

                print('!! Alfred-Json-158 Format Error:',jsonIndex)

            else:
                NodeID = json158Dict[jsonIndex]['node_id'].strip()
                NodeMAC = NodeID[0:2] + ':' + NodeID[2:4] + ':' + NodeID[4:6] + ':' + NodeID[6:8] + ':' + NodeID[8:10] + ':' + NodeID[10:12]

                if not MacAdrTemplate.match(NodeMAC):
                    print('!! Invalid NodeMAC:',jsonIndex,'=',NodeMAC)

                elif not GwAllMacTemplate.match(NodeMAC):
                    if not 'mac' in json158Dict[jsonIndex]['network']:
                        print('++ No MAC in Alfred-158:',jsonIndex,'=',NodeMAC)
                    elif json158Dict[jsonIndex]['network']['mac'].strip() != NodeMAC:
                        print('++ MAC Mismatch:',jsonIndex,'->',NodeMAC,'<>',json158Dict[jsonIndex]['network']['mac'].strip())

                    if NodeMAC not in self.ffNodeDict:
                        self.ffNodeDict[NodeMAC] = {
                            'RawKey': None,
                            'Name': json158Dict[jsonIndex]['hostname'],
                            'Status': ' ',
                            'last_online': JsonUnixTime,
                            'Clients': 0,
                            'Latitude': None,
                            'Longitude': None,
                            'ZIP': None,
                            'Region': '??',
                            'DestSeg': 99,
                            'oldGluon': '?',
                            'Segment': None,
                            'SegMode': 'auto',
                            'KeyDir': '',
                            'KeyFile': '',
                            'FastdKey':'',
                            'InCloud': 0,
                            'Neighbours': []
                        }

                        self.MAC2NodeIDDict[NodeMAC] = NodeMAC
                        print('++ Node added:    ',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'))

                    #---------- verify Node Infos ----------
                    if self.ffNodeDict[NodeMAC]['Name'] != json158Dict[jsonIndex]['hostname']:
                        print('++ Hostname mismatch:',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'),'->',self.ffNodeDict[NodeMAC]['Name'].encode('utf-8'))

                    if self.ffNodeDict[NodeMAC]['Status'] not in OnlineStates:
                        self.ffNodeDict[NodeMAC]['Status'] = ' '
#                        print('++ Node is online:',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'))

                    if 'mesh' in json158Dict[jsonIndex]['network']:
                        if 'bat0' in json158Dict[jsonIndex]['network']['mesh']:
                            if 'interfaces' in json158Dict[jsonIndex]['network']['mesh']['bat0']:
                                for InterfaceType in json158Dict[jsonIndex]['network']['mesh']['bat0']['interfaces']:
                                    if InterfaceType in ['tunnel','wireless','other']:
                                        for MeshMAC in json158Dict[jsonIndex]['network']['mesh']['bat0']['interfaces'][InterfaceType]:
                                            if MeshMAC not in self.MAC2NodeIDDict:
                                                print('++ Mesh MAC added:',MeshMAC,'->',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'))
                                                self.MAC2NodeIDDict[MeshMAC] = NodeMAC
                                                self.__AddGluonMACs(NodeMAC,MeshMAC)
                                            elif self.MAC2NodeIDDict[MeshMAC] != NodeMAC:
                                                print('!! Mesh MAC mismatch:',MeshMAC,'->',NodeMAC,'<>',self.MAC2NodeIDDict[MeshMAC])

                    if 'addresses' in json158Dict[jsonIndex]['network']:
                        for NodeAddress in json158Dict[jsonIndex]['network']['addresses']:
                            if NodeAddress[0:12] == 'fd21:b4dc:4b':
                                if NodeAddress[12:14] == '1e':
                                    self.ffNodeDict[NodeMAC]['Segment'] = 0
                                else:
                                    self.ffNodeDict[NodeMAC]['Segment'] = int(NodeAddress[12:14])

                            if NodeAddress[0:9] == 'fd21:711:' and 'status-page' in json158Dict[jsonIndex]['software']:
                                self.ffNodeDict[NodeMAC]['oldGluon'] = ' '

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

        try:
            Afred159HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred159Name,timeout=10)
            HttpDate = datetime.datetime.strptime(Afred159HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate

            if StatusAge.total_seconds() > 900:
                Afred159HTTP.close()
                self.__alert('++ alfred-json-159.json is too old !!!')
                self.AnalyseOnly = True
                return

            json159Dict = json.loads(Afred159HTTP.read().decode('utf-8'))
            Afred159HTTP.close()
        except:
            self.__alert('++ Error on loading alfred-json-159.json !!!')
            self.AnalyseOnly = True
            return

        print('Analysing alfred-json-159.json ...')

        for jsonIndex in json159Dict:
            NodeID = json159Dict[jsonIndex]['node_id'].strip()
            NodeMAC = NodeID[0:2] + ':' + NodeID[2:4] + ':' + NodeID[4:6] + ':' + NodeID[6:8] + ':' + NodeID[8:10] + ':' + NodeID[10:12]

            if not GwAllMacTemplate.match(NodeMAC):
                if not MacAdrTemplate.match(NodeMAC):
                    print('++ ERROR 159 NodeItem Format:',NodeMAC)

                elif NodeMAC not in self.ffNodeDict:
                    print('+++ Not in self.ffNodeDict:',NodeMAC)

                else:
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

        try:
            Afred160HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred160Name,timeout=10)
            HttpDate = datetime.datetime.strptime(Afred160HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate

            if StatusAge.total_seconds() > 900:
                Afred160HTTP.close()
                self.__alert('++ alfred-json-160.json is too old !!!')
                self.AnalyseOnly = True
                return

            json160 = json.loads(Afred160HTTP.read().decode('utf-8'))
            Afred160HTTP.close()
        except:
            self.__alert('++ Error on loading alfred-json-160.json !!!')
            self.AnalyseOnly = True
            return

        print('Analysing alfred-json-160.json ...')

        for NodeItem in json160:
            ffNodeID = json160[NodeItem]['node_id'].strip()
            ffNodeMAC = ffNodeID[0:2] + ':' + ffNodeID[2:4] + ':' + ffNodeID[4:6] + ':' + ffNodeID[6:8] + ':' + ffNodeID[8:10] + ':' + ffNodeID[10:22]

            if ffNodeMAC in self.ffNodeDict and self.ffNodeDict[ffNodeMAC]['Status'] != '?':
                for MeshIF in ['batadv','wifi']:
                    if MeshIF in json160[NodeItem]:
                        for batXX in json160[NodeItem][MeshIF]:
                            if batXX not in self.MAC2NodeIDDict:
                                print('++ batXX missing:',batXX)
                                self.MAC2NodeIDDict[batXX] = ffNodeMAC

                            if 'neighbours' in json160[NodeItem][MeshIF][batXX]:
                                for ffNeighbour in json160[NodeItem][MeshIF][batXX]['neighbours']:
                                    if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                        (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                        self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)
    #                                    print('++ New Neigbour found:',self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'->',ffNeighbour)

                                        if ffNeighbour not in self.MAC2NodeIDDict:
                                            print('++ Neigbour MAC unknown:',self.ffNodeDict[ffNodeMAC]['Segment'],self.ffNodeDict[ffNodeMAC]['Status'],ffNodeMAC,'=',self.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'),'->',ffNeighbour)
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
                RawJsonDict = json.loads(RawJsonHTTP.read().decode('utf-8'))
                RawJsonHTTP.close()
            except:
                print('** need retry ...')
                RawJsonDict = None
                time.sleep(2)

        if RawJsonDict is None:
            self.__alert('++ Error on loading raw.json !!!\n')
            self.AnalyseOnly = True
            return

        print('Analysing raw.json ...')

        UtcTime  = datetime.datetime.utcnow()
        UnixTime = time.mktime(UtcTime.timetuple())

        for ffNodeKey in RawJsonDict.keys():
            if 'nodeinfo' in RawJsonDict[ffNodeKey] and 'statistics' in RawJsonDict[ffNodeKey] and 'lastseen' in RawJsonDict[ffNodeKey]:

                if RawJsonDict[ffNodeKey]['nodeinfo']['node_id'] != ffNodeKey or RawJsonDict[ffNodeKey]['statistics']['node_id'] != ffNodeKey:
                    print('++ NodeID-Mismatch:',RawJsonDict[ffNodeKey]['nodeinfo']['node_id'],ffNodeKey)
                    continue

                ffNodeMAC = RawJsonDict[ffNodeKey]['nodeinfo']['network']['mac'].strip()

                if not MacAdrTemplate.match(ffNodeMAC):
                    print('!! Invalid MAC Format:',ffNodeKey,ffNodeMAC)
                    continue

                ffNodeID = ffNodeMAC.replace(':','')

                if ffNodeID != ffNodeKey[:12]:
                    print('++ NodeID-MAC-Mismatch:',ffNodeKey,'<->',ffNodeID,'=',ffNodeMAC)
                    continue

                if not GwAllMacTemplate.match(ffNodeMAC):
                    if ((not 'software' in RawJsonDict[ffNodeKey]['nodeinfo']) or
                          (not 'firmware' in RawJsonDict[ffNodeKey]['nodeinfo']['software']) or
                          (not 'release' in RawJsonDict[ffNodeKey]['nodeinfo']['software']['firmware']) or
                          (RawJsonDict[ffNodeKey]['nodeinfo']['software']['firmware']['release'] is None) or
                          (not 'network' in RawJsonDict[ffNodeKey]['nodeinfo'])):
                        print('++ Invalid Record:',ffNodeKey,'=',ffNodeMAC)
                        continue

                    LastSeen = time.mktime(datetime.datetime.strptime(RawJsonDict[ffNodeKey]['lastseen'], '%Y-%m-%dT%H:%M:%S.%fZ').timetuple())

                    if ffNodeMAC in self.ffNodeDict:

                        if self.ffNodeDict[ffNodeMAC]['RawKey'] is None:
                            if self.ffNodeDict[ffNodeMAC]['last_online'] > LastSeen:
                                continue    # Alfred is newer
#                            else:
#                                print('-+ Updating:',ffNodeKey,'=',ffNodeMAC,'=',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('UTF-8'))
                        else:
                            if self.ffNodeDict[ffNodeMAC]['last_online'] > RawJsonDict[ffNodeKey]['lastseen']:
                                continue    # newer Duplicate already in raw.json
                            else:
                                print('-+ Upd. RAW:',ffNodeKey,'=',ffNodeMAC,'=',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('UTF-8'))
                    else:
                        print('++ New Node:',ffNodeKey,'=',ffNodeMAC,'=',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('UTF-8'))
                        self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC

                        self.ffNodeDict[ffNodeMAC] = {
                            'RawKey':'',
                            'Name':RawJsonDict[ffNodeKey]['nodeinfo']['hostname'],
                            'Status':'#',
                            'last_online':0,
                            'Clients':0,
                            'Latitude':None,
                            'Longitude':None,
                            'ZIP':None,
                            'Region':'??',
                            'DestSeg':99,
                            'oldGluon':'?',
                            'Segment':None,
                            'SegMode':'auto',
                            'KeyDir':'',
                            'KeyFile':'',
                            'FastdKey':'',
                            'InCloud':0,
                            'Neighbours':[]
                        }


                    #---------- new Node or newer info than alfred ----------
                    self.ffNodeDict[ffNodeMAC]['RawKey'] = ffNodeKey
                    self.ffNodeDict[ffNodeMAC]['last_online'] = LastSeen

                    if 'clients' in RawJsonDict[ffNodeKey]['statistics']:
                        self.ffNodeDict[ffNodeMAC]['Clients'] = int(RawJsonDict[ffNodeKey]['statistics']['clients']['total'])
                    else:
                        self.ffNodeDict[ffNodeMAC]['Clients'] = 0

                    if self.ffNodeDict[ffNodeMAC]['Name'] != RawJsonDict[ffNodeKey]['nodeinfo']['hostname']:
                        print('++ Hostname mismatch:',ffNodeMAC,'=',self.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'),'->',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('utf-8'))
                        self.ffNodeDict[ffNodeMAC]['Name'] = RawJsonDict[ffNodeKey]['nodeinfo']['hostname']

                    if 'addresses' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                        for NodeAddress in RawJsonDict[ffNodeKey]['nodeinfo']['network']['addresses']:
                            if NodeAddress[0:9] == 'fd21:711:' and 'status-page' in RawJsonDict[ffNodeKey]['nodeinfo']['software']:
                                self.ffNodeDict[ffNodeMAC]['oldGluon'] = ' '

                    if 'gateway' in RawJsonDict[ffNodeKey]['statistics']:
                        if RawJsonDict[ffNodeKey]['statistics']['gateway'][:9] == '02:00:0a:':
                            self.ffNodeDict[ffNodeMAC]['Segment'] = int(RawJsonDict[ffNodeKey]['statistics']['gateway'][13:14])
                        elif GwNewMacTemplate.match(RawJsonDict[ffNodeKey]['statistics']['gateway']):
                            self.ffNodeDict[ffNodeMAC]['Segment'] = int(RawJsonDict[ffNodeKey]['statistics']['gateway'][10:11])

                    if 'location' in RawJsonDict[ffNodeKey]['nodeinfo']:
                        if 'latitude' in RawJsonDict[ffNodeKey]['nodeinfo']['location'] and 'longitude' in RawJsonDict[ffNodeKey]['nodeinfo']['location']:
                            self.ffNodeDict[ffNodeMAC]['Latitude']  = RawJsonDict[ffNodeKey]['nodeinfo']['location']['latitude']
                            self.ffNodeDict[ffNodeMAC]['Longitude'] = RawJsonDict[ffNodeKey]['nodeinfo']['location']['longitude']

                        if 'zip' in RawJsonDict[ffNodeKey]['nodeinfo']['location']:
                            self.ffNodeDict[ffNodeMAC]['ZIP'] = str(RawJsonDict[ffNodeKey]['nodeinfo']['location']['zip'])[:5]

                    if 'mesh' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                        for InterfaceType in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh']['bat0']['interfaces']:
                            for MeshMAC in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh']['bat0']['interfaces'][InterfaceType]:
                                self.MAC2NodeIDDict[MeshMAC] = ffNodeMAC
                                self.__AddGluonMACs(ffNodeMAC,MeshMAC)
                    elif 'mesh_interfaces' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                        for MeshMAC in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh_interfaces']:
                            self.MAC2NodeIDDict[MeshMAC] = ffNodeMAC
                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)

                    if 'neighbours' in RawJsonDict[ffNodeKey]:
                        for InterfaceType in ['batadv','wifi']:
                            if InterfaceType in RawJsonDict[ffNodeKey]['neighbours']:
                                for MeshMAC in RawJsonDict[ffNodeKey]['neighbours'][InterfaceType]:

                                    if 'neighbours' in RawJsonDict[ffNodeKey]['neighbours'][InterfaceType][MeshMAC]:
                                        for ffNeighbour in RawJsonDict[ffNodeKey]['neighbours'][InterfaceType][MeshMAC]['neighbours']:
                                            if ((MacAdrTemplate.match(ffNeighbour) and not GwAllMacTemplate.match(ffNeighbour)) and
                                                (ffNeighbour not in self.ffNodeDict[ffNodeMAC]['Neighbours'])):

                                                self.ffNodeDict[ffNodeMAC]['Neighbours'].append(ffNeighbour)

                    if UnixTime - LastSeen < MaxOfflineTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = ' '   # -> online
                    elif UnixTime - LastSeen > MaxInactiveTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = '?'   # -> inactive

                    if 'mesh_vpn' in RawJsonDict[ffNodeKey]['statistics']:
                        if 'groups' in RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']:
                            if 'backbone' in RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']['groups']:
                                if 'peers' in RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']['groups']['backbone']:
                                    GWpeers = RawJsonDict[ffNodeKey]['statistics']['mesh_vpn']['groups']['backbone']['peers']

                                    for Uplink in GWpeers:
                                        if GWpeers[Uplink] is not None:
                                            if 'established' in GWpeers[Uplink]:
                                                if self.ffNodeDict[ffNodeMAC]['Status'] == ' ':
                                                    self.ffNodeDict[ffNodeMAC]['Status'] = 'V'

            else:
                print('** Invalid Record:',ffNodeKey)

        print('... done.\n')
        return



    #=========================================================================
    # Method "AddNode"
    #
    #   Adds a Node { 'SegDir','SegMode','VpnMAC','PeerMAC','PeerName','PeerKey' }
    #
    #=========================================================================
    def AddNode(self,KeyIndex,KeyInfo):

        ffNodeMAC = KeyInfo['PeerMAC']

        if not MacAdrTemplate.match(ffNodeMAC):
            if MacAdrTemplate.match(KeyInfo['VpnMAC']):
                if KeyInfo['VpnMAC'] in self.MAC2NodeIDDict:
                    ffNodeMAC = self.MAC2NodeIDDict[KeyInfo['VpnMAC']]

        if MacAdrTemplate.match(ffNodeMAC):
            if not ffNodeMAC in self.ffNodeDict:

                self.ffNodeDict[ffNodeMAC] = {
                    'RawKey': None,
                    'Name': KeyInfo['PeerName'],
                    'Status': '?',
                    'last_online': 0,
                    'Clients': 0,
                    'Latitude':None,
                    'Longitude':None,
                    'ZIP':None,
                    'Region': '??',
                    'DestSeg': 99,
                    'oldGluon': '?',
                    'Segment': int(KeyInfo['SegDir'][3:]),
                    'SegMode': KeyInfo['SegMode'],
                    'KeyDir': KeyInfo['SegDir'],
                    'KeyFile': KeyIndex,
                    'FastdKey': KeyInfo['PeerKey'],
                    'InCloud': 0,
                    'Neighbours': []
                }

                self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC
                self.__AddGluonMACs(ffNodeMAC,KeyInfo['VpnMAC'])

                if KeyInfo['VpnMAC'] != '':
                    print('!! New Node:      ',KeyInfo['SegDir'],'/',ffNodeMAC,'=',KeyInfo['PeerName'].encode('utf-8'))

            else:   # updating existing node
                self.ffNodeDict[ffNodeMAC]['SegMode']  = KeyInfo['SegMode']
                self.ffNodeDict[ffNodeMAC]['KeyDir']   = KeyInfo['SegDir']
                self.ffNodeDict[ffNodeMAC]['KeyFile']  = KeyIndex
                self.ffNodeDict[ffNodeMAC]['FastdKey'] = KeyInfo['PeerKey']

            if KeyInfo['VpnMAC'] != '':
                if self.ffNodeDict[ffNodeMAC]['Status'] == '?':
                    print('!! Node is alive: ',KeyInfo['SegDir'],'/',KeyInfo['VpnMAC'],'->',ffNodeMAC,'=',KeyInfo['PeerName'].encode('utf-8'))
                elif self.ffNodeDict[ffNodeMAC]['Status'] != 'V':
                    print('++ Node is online:',KeyInfo['SegDir'],'/',KeyInfo['VpnMAC'],'->',ffNodeMAC,'=',KeyInfo['PeerName'].encode('utf-8'))

                self.ffNodeDict[ffNodeMAC]['Segment'] = int(KeyInfo['SegDir'][3:])
                self.ffNodeDict[ffNodeMAC]['Status'] = 'V'

        return



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
    #   Verify Tunnel-MAC / Main-MAC with batman Global Translation Table
    #
    #==============================================================================
    def GetBatmanNodeMACs(self,SegmentList):

        print('\nAnalysing Batman TG ...')

        for ffSeg in SegmentList:
            print('... Segment',ffSeg,'...')
            BatctlCmd = ('/usr/sbin/batctl -m bat%02d tg' % (ffSeg)).split()
            NodeCount = 0
            ClientCount = 0

            try:
                BatctlTG = subprocess.run(BatctlCmd, stdout=subprocess.PIPE)
                BatctlResult = BatctlTG.stdout.decode('utf-8')
            except:
                print('++ ERROR accessing batman:',BatctlCmd)
            else:
                for BatctlLine in BatctlResult.split('\n'):
                    BatctlInfo = BatctlLine.replace('(',' ').replace(')',' ').split()
                    #----- BatctlInfo[1] = Client-MAC  /  BatctlInfo[5] = Node-Tunnel-MAC -----

                    if len(BatctlInfo) == 9 and MacAdrTemplate.match(BatctlInfo[1]) and not GwAllMacTemplate.match(BatctlInfo[1]):
                        if BatctlInfo[2] == '-1' and MacAdrTemplate.match(BatctlInfo[5]) and not GwAllMacTemplate.match(BatctlInfo[5]):

                            if BatctlInfo[5][:1] == BatctlInfo[1][:1] and BatctlInfo[5][9:] == BatctlInfo[1][9:]:  # old Gluon MAC schema
                                BatmanMacList = self.GenerateGluonMACsOld(BatctlInfo[1])
                            else:  # new Gluon MAC schema
                                BatmanMacList = self.GenerateGluonMACsNew(BatctlInfo[1])

                            if BatctlInfo[5] in BatmanMacList:  # Data is from Node
                                NodeCount += 1

                                if BatctlInfo[5] in self.MAC2NodeIDDict:
                                    if self.MAC2NodeIDDict[BatctlInfo[5]] != BatctlInfo[1]:
                                        print('!! MAC mismatch Tunnel -> Client: Batman <> Alfred:',BatctlInfo[5],'->',BatctlInfo[1],'<>',self.MAC2NodeIDDict[BatctlInfo[5]])
                                    elif BatctlInfo[1] in self.ffNodeDict:
                                        if self.ffNodeDict[BatctlInfo[1]]['Status'] != 'V':
                                            self.ffNodeDict[BatctlInfo[1]]['Status'] = ' '
                                    else:
                                        print('++ New Node in Batman:',ffSeg,'/',BatctlInfo[1])

                                else:
                                    print('++ Unknown MAC in Batman:',ffSeg,'->',BatctlInfo[5],'=',BatctlInfo[1])

                            else:  # Data is from Client
                                ClientCount += 1

            print('... Nodes / Clients:',NodeCount,'/',ClientCount)

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
#                                    print(BatctlInfo[1],'<>',MeshMAC)
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
    # private function "__SetupZipData"
    #
    #     Load ZIP File of OpenGeoDB Project
    #
    #-------------------------------------------------------------
    def __SetupZipData(self,Path):

        print('Setting up ZIP Data ...')

        Zip2GpsDict = None
        ZipCount = 0

        try:
            with open(os.path.join(Path,ZipTableName), mode='r') as Zip2GpsFile:
                Zip2GpsDict = json.load(Zip2GpsFile)
        except:
            print('!! ERROR on setting up ZIP-Data')
            Zip2GpsDict = None
        else:
            ZipCount = len(Zip2GpsDict)

        print('... ZIP-Codes loaded:',ZipCount,'\n')
        return Zip2GpsDict



    #-------------------------------------------------------------
    # private function "__SetupRegionData"
    #
    #     Load Region Json Files and setup polygons
    #
    #-------------------------------------------------------------
    def __SetupRegionData(self,Path):

        print('Setting up Region Data ...')

        RegionDict = {
            'Center_lat': None,
            'Center_lon': None,
            'ValidArea' : Polygon([(35.0,-12.0),(72.0,-12.0),(72.0,30.0),(35.0,30.0)]),
            'Q1_Segment': None,
            'Q2_Segment': None,
            'Q3_Segment': None,
            'Q4_Segment': None,
            'Polygons'  : {},
            'Segments'  : {}
        }

        JsonFileList = glob(os.path.join(Path,'*/*.json'))
        RegionCount = 0

        try:
            for FileName in JsonFileList:
                Region  = os.path.basename(FileName.split(".")[0])
                Segment = int(os.path.dirname(FileName).split("/")[-1])

                with open(FileName,"r") as JsonFile:
                    GeoJson = json.load(JsonFile)

                if "geometries" in GeoJson:
                    Track = GeoJson["geometries"][0]["coordinates"][0][0]
                elif "coordinates" in GeoJson:
                    Track = GeoJson["coordinates"][0][0]
                else:
                    Track = None
                    print('Problem parsing %s' % FileName)
                    continue

                Shape = []

                for t in Track:
                    Shape.append( (t[1],t[0]) )

                Area = Polygon(Shape)

                RegionDict['Polygons'][Region] = Area
                RegionDict['Segments'][Region] = Segment
                RegionCount += 1

                if Region[:1] == '0':
                    CenterPoint = Area.centroid
                    RegionDict['Center_lat'] = CenterPoint.y
                    RegionDict['Center_lon'] = CenterPoint.x

                if Region[:1] == '1': RegionDict['Q1_Segment'] = Segment
                if Region[:1] == '2': RegionDict['Q2_Segment'] = Segment
                if Region[:1] == '3': RegionDict['Q3_Segment'] = Segment
                if Region[:1] == '4': RegionDict['Q4_Segment'] = Segment

        except:
            RegionDict = None
        else:
            if ((RegionDict['Center_lat'] is None or RegionDict['Center_lon'] is None) or
                (RegionDict['Q1_Segment'] is None or RegionDict['Q2_Segment'] is None) or
                (RegionDict['Q3_Segment'] is None or RegionDict['Q4_Segment'] is None)):

                RegionDict = None

        print('... Region Areas loaded:',RegionCount,'\n')
        return RegionDict



    #-------------------------------------------------------------
    # private function "__GetSegmentFromGPS"
    #
    #     Get Segment from GPS using region polygons
    #
    #-------------------------------------------------------------
    def __GetSegmentFromGPS(self,lat,lon,ffNodeMAC,RegionDict):

        Segment = None

        if lat is not None and lon is not None:
            NodeLocation = Point(lat,lon)

            if RegionDict['ValidArea'].intersects(NodeLocation):

                for Region in RegionDict['Polygons'].keys():
                    if RegionDict['Polygons'][Region].intersects(NodeLocation):
                        Segment = RegionDict['Segments'][Region]
                        break

                if Segment is None:
                    if lat > RegionDict['Center_lat']:
                        if lon > RegionDict['Center_lon']:  # Quadrant 1
                            Segment = RegionDict['Q1_Segment']
                        else:  # Quadrant 2
                            Segment = RegionDict['Q2_Segment']
                    else:
                        if lon < RegionDict['Center_lon']:  # Quadrant 3
                            Segment = RegionDict['Q3_Segment']
                        else:  # Quadrant 4
                            Segment = RegionDict['Q4_Segment']

            else:
                print('!! Invalid Location:',ffNodeMAC,'=',self.ffNodeDict[ffNodeMAC]['Name'].encode('utf-8'),'->',lat,'|',lon)

        return Segment




    #==============================================================================
    # Method "SetDesiredSegments"
    #
    #   Get Segment from Location (GPS Data or ZIP-Code)
    #==============================================================================
    def SetDesiredSegments(self,RegionDataPath):

        print('Setting up Desired Segments from GPS Data or ZIP-Code ...')

        isOK = True
        RegionDict  = self.__SetupRegionData(RegionDataPath)
        Zip2PosDict = self.__SetupZipData(RegionDataPath)
        OSMapi      = overpy.Overpass()

        if RegionDict is None or Zip2PosDict is None:
            self.__alert('!! No Region Data available !!!')
            self.AnalyseOnly = True
            isOK = False
        else:
            for ffNodeMAC in self.ffNodeDict.keys():
                if self.ffNodeDict[ffNodeMAC]['Status'] != '?':
                    lat = None
                    lon = None
                    Segment = None

                    if self.ffNodeDict[ffNodeMAC]['Latitude'] is not None and self.ffNodeDict[ffNodeMAC]['Longitude'] is not None:

                        lat = self.ffNodeDict[ffNodeMAC]['Latitude']
                        lon = self.ffNodeDict[ffNodeMAC]['Longitude']

                        if lat < lon:
                            lat = self.ffNodeDict[ffNodeMAC]['Longitude']
                            lon = self.ffNodeDict[ffNodeMAC]['Latitude']

                        Segment = self.__GetSegmentFromGPS(lat,lon,ffNodeMAC,RegionDict)


                    if self.ffNodeDict[ffNodeMAC]['ZIP'] is not None:
                        ZipCode = self.ffNodeDict[ffNodeMAC]['ZIP'][:5]
                        ZipSegment = None

                        if ZipTemplate.match(ZipCode):
                            print('++ Get Position from ZIP-Code:',ffNodeMAC,'->',ZipCode)    #<<<<<<<<<<<<<<<<<<<<<<<<<<

                            if ZipCode in Zip2PosDict:
                                lat = float(Zip2PosDict[ZipCode]['lat'])
                                lon = float(Zip2PosDict[ZipCode]['lon'])
                                ZipSegment = self.__GetSegmentFromGPS(lat,lon,ffNodeMAC,RegionDict)

                            if ZipSegment is None:    # Fallback to online query of OSM ...
                                lat = 0.0
                                lon = 0.0

                                try:
                                    query = 'rel[postal_code="%s"];out center;' % (ZipCode)
                                    result = OSMapi.query(query)

                                    for relation in result.relations:
                                        lat = relation.center_lat
                                        lon = relation.center_lon
                                        ZipSegment = self.__GetSegmentFromGPS(lat,lon,ffNodeMAC,RegionDict)
                                        break
                                except:
                                    ZipSegment = None

                            print('>>> GeoSegment / ZipSegment =',Segment,'/',ZipSegment)    #<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

                            if Segment is not None:
                                if ZipSegment is not None and ZipSegment != Segment:
                                    print('!! Segment Mismatch Geo <> ZIP:',Segment,'<>',ZipSegment)
                            elif ZipSegment is not None:
                                Segment = ZipSegment
                                print('>>> Segment set by ZIP-Code:',Segment)

                        else:
                            print('!! Invalid ZIP-Code:',ZipCode)

                    if Segment is not None:
                        self.ffNodeDict[ffNodeMAC]['DestSeg'] = Segment

        print('... done.\n')
        return isOK

