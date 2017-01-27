#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  class_ffNodeInfo.py                                                                    #
#                                                                                         #
#  Loading and analysing Data of all Nodes.                                               #
#                                                                                         #
#                                                                                         #
#  Needed json-Files:                                                                     #
#                                                                                         #
#       raw.json             -> Node Names and Information                                #
#       nodesdb.json         -> Region = Segment                                          #
#       alfred-json-158.json -> Nodeinfos                                                 #
#       alfred-json-159.json -> VPN-Uplinks                                               #
#       alfred-json-160.json -> Neighbors                                                 #
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
import urllib.request
import time
import datetime
import json
import re
import hashlib
import fcntl



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

MaxInactiveTime    = 10 * 86400     # 10 Days (in Seconds)
MaxOfflineTime     = 30 * 60        # 30 Minutes (in Seconds)
MaxStatisticsData  = 12 * 24 * 7    # 1 Week wit Data all 5 Minutes

OnlineStates       = [' ','V']      # online, online with VPN-Uplink


NodesDbName    = 'nodesdb.json'
Alfred158Name  = 'alfred-json-158.json'
Alfred159Name  = 'alfred-json-159.json'
Alfred160Name  = 'alfred-json-160.json'

StatFileName   = 'SegStatistics.json'


GwNameTemplate    = re.compile('^gw[01][0-9]{1,2}')
GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[5-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate  = re.compile('^02:00:(3[5-9])(:[0-9a-f]{2}){3}')

MacAdrTemplate    = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
NodeIdTemplate    = re.compile('^[0-9a-f]{12}$')

PeerTemplate      = re.compile('^ffs-[0-9a-f]{12}')
PeerTemplate1     = re.compile('^ffs[-_][0-9a-f]{12}')
PeerTemplate2     = re.compile('^ffs[0-9a-f]{12}')

SegmentTemplate   = re.compile('^[0-9]{2}$')

KeyDirTemplate    = re.compile('^vpn[0-9]{2}$')
FastdKeyTemplate  = re.compile('^[0-9a-f]{64}$')


GoodOldGluonList  = [
    '0.6-g.271e864',
    '0.6-g.88bdc98',
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
        self.SegmentLoadDict = {}       # Dictionary of Segments with their load (Nodes + Clients)
        self.Alerts          = []       # List of  Alert-Messages
        self.AnalyseOnly     = False    # Locking automatic Actions due to inconsistent Data

        # private Attributes
        self.__AlfredURL = AlfredURL
        self.__RawAccess = RawAccess

        self.__MeshCloudDict = {}       # Dictionary of Mesh-Clouds with List of Member-Nodes
        self.__SegmentDict   = {}       # Dictionary of Segments with their Number of Nodes and Clients
        self.__NodeMoveDict  = {}       # Git Moves of Nodes from one Segment to another

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



    #-----------------------------------------------------------------------
    # private function "__GenerateGluonMACsOld(MainMAC)"
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
    #-----------------------------------------------------------------------
    def __GenerateGluonMACsOld(self,MainMAC):

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



    #-----------------------------------------------------------------------
    # private function "__GenerateGluonMACsNew(MainMAC)"
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
    #-----------------------------------------------------------------------
    def __GenerateGluonMACsNew(self,MainMAC):

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
            GluonMacList = self.__GenerateGluonMACsNew(MainMAC)

            if not MeshMAC in GluonMacList:
                GluonMacList = self.__GenerateGluonMACsOld(MainMAC)

                if not MeshMAC in GluonMacList:
                    GluonMacList = [MeshMAC]

        else:   # only MainMAC available
            GluonMacList = self.__GenerateGluonMACsNew(MainMAC)

            knownMAC = False

            for NewMAC in GluonMacList:
                if NewMAC in self.MAC2NodeIDDict:
                    knownMAC = True
                    break

            if not knownMAC:
                GluonMacList = self.__GenerateGluonMACsOld(MainMAC)

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

        try:
            NodesDbJsonHTTP = urllib.request.urlopen(self.__AlfredURL+NodesDbName)
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

                    if 'clients' in jsonDbDict[DbIndex]:
                        TotalClients = jsonDbDict[DbIndex]['clients']['total']
                    else:
                        TotalClients = 0

                    self.ffNodeDict[ffNodeMAC] = {
                        'RawKey':None,
                        'Name':jsonDbDict[DbIndex]['hostname'],
                        'Status':'#',
                        'last_online':jsonDbDict[DbIndex]['last_online'],
                        'Clients':TotalClients,
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
                        if jsonDbDict[DbIndex]['status'] == 'online':
                            self.ffNodeDict[ffNodeMAC]['Status'] = ' '

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
            Afred158HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred158Name)
            HttpDate = datetime.datetime.strptime(Afred158HTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate

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
                        print('++ Node not in self.ffNodeDict:',NodeMAC)
                    else:
                        #---------- verify Node Infos ----------
                        if self.ffNodeDict[NodeMAC]['Name'] != json158Dict[jsonIndex]['hostname']:
                            print('++ Hostname mismatch:',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'),'->',self.ffNodeDict[NodeMAC]['Name'].encode('utf-8'))

                        if not self.ffNodeDict[NodeMAC]['Status'] in OnlineStates:
                            self.ffNodeDict[NodeMAC]['Status'] = ' '
                            print('++ Node is online:',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'))

                        if 'mesh' in json158Dict[jsonIndex]['network']:
                            if 'bat0' in json158Dict[jsonIndex]['network']['mesh']:
                                if 'interfaces' in json158Dict[jsonIndex]['network']['mesh']['bat0']:
                                    for InterfaceType in json158Dict[jsonIndex]['network']['mesh']['bat0']['interfaces']:
                                        if InterfaceType in ['tunnel','wireless','other']:
                                            for MeshMAC in json158Dict[jsonIndex]['network']['mesh']['bat0']['interfaces'][InterfaceType]:
                                                if not MeshMAC in self.MAC2NodeIDDict:
                                                    print('++ Mesh MAC added:',MeshMAC,'->',NodeMAC,'=',json158Dict[jsonIndex]['hostname'].encode('utf-8'))
                                                    self.MAC2NodeIDDict[MeshMAC] = NodeMAC
                                                elif self.MAC2NodeIDDict[MeshMAC] != NodeMAC:
                                                    print('!! Mesh MAC mismatch:',MeshMAC,'->',NodeMAC,'<>',self.MAC2NodeIDDict[MeshMAC])

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
            Afred159HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred159Name)
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
                                    GWlist = []

                                    for Uplink in GWpeers:
                                        if GWpeers[Uplink] is not None:
                                            if 'established' in GWpeers[Uplink]:
                                                GWlist.append(Uplink[2:])
                                                self.ffNodeDict[NodeMAC]['Status'] = 'V'

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
            Afred160HTTP = urllib.request.urlopen(self.__AlfredURL+Alfred160Name)
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

        try:
            passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passman.add_password(None, self.__RawAccess['URL'], self.__RawAccess['Username'], self.__RawAccess['Password'])
            authhandler = urllib.request.HTTPBasicAuthHandler(passman)
            opener = urllib.request.build_opener(authhandler)
            urllib.request.install_opener(opener)

            RawJsonHTTP = urllib.request.urlopen(self.__RawAccess['URL'])
            RawJsonDict = json.loads(RawJsonHTTP.read().decode('utf-8'))
            RawJsonHTTP.close()
        except:
            self.__alert('++ Error on loading raw.json !!!')
            self.AnalyseOnly = True
            return

        print('Analysing raw.json ...')

        UtcTime  = datetime.datetime.utcnow()
        UnixTime = time.mktime(datetime.datetime.utcnow().timetuple())

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
                            else:
                                print('-+ Upd. from Alfred:',ffNodeKey,'=',ffNodeMAC,'=',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('UTF-8'))
                        else:
                            if self.ffNodeDict[ffNodeMAC]['last_online'] > RawJsonDict[ffNodeKey]['lastseen']:
                                continue    # newer Duplicate already in raw.json
                            else:
                                print('-+ Upd. from RAW:',ffNodeKey,'=',ffNodeMAC,'=',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('UTF-8'))
                    else:
                        print('++ New Node:',ffNodeKey,'=',ffNodeMAC,'=',RawJsonDict[ffNodeKey]['nodeinfo']['hostname'].encode('UTF-8'))
                        self.MAC2NodeIDDict[ffNodeMAC] = ffNodeMAC

                        self.ffNodeDict[ffNodeMAC] = {
                            'RawKey':'',
                            'Name':RawJsonDict[ffNodeKey]['nodeinfo']['hostname'],
                            'Status':'#',
                            'last_online':0,
                            'Clients':0,
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

                    self.ffNodeDict[ffNodeMAC]['RawKey'] = ffNodeKey
                    self.ffNodeDict[ffNodeMAC]['last_online'] = LastSeen

                    if 'clients' in RawJsonDict[ffNodeKey]['statistics']:
                        self.ffNodeDict[ffNodeMAC]['Clients'] = RawJsonDict[ffNodeKey]['statistics']['clients']['total']
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

                    if 'mesh_interfaces' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                        for MeshMAC in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh_interfaces']:
                            self.MAC2NodeIDDict[MeshMAC] = ffNodeMAC
                            self.__AddGluonMACs(ffNodeMAC,MeshMAC)
                    elif 'mesh' in RawJsonDict[ffNodeKey]['nodeinfo']['network']:
                        for InterfaceType in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh']['bat0']['interfaces']:
                            for MeshMAC in RawJsonDict[ffNodeKey]['nodeinfo']['network']['mesh']['bat0']['interfaces'][InterfaceType]:
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
                        self.ffNodeDict[ffNodeMAC]['Status'] = ' '   # online
                    elif UnixTime - LastSeen > MaxInactiveTime:
                        self.ffNodeDict[ffNodeMAC]['Status'] = '?'   # inactive

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
    def AddNode(self,KeyIndex,ffNode):

        if not MacAdrTemplate.match(ffNode['PeerMAC']):
            if MacAdrTemplate.match(ffNode['VpnMAC']):
                if ffNode['VpnMAC'] in self.MAC2NodeIDDict:
                    ffNode['PeerMAC'] = self.MAC2NodeIDDict[ffNode['VpnMAC']]

        if MacAdrTemplate.match(ffNode['PeerMAC']):
            if not ffNode['PeerMAC'] in self.ffNodeDict:

                self.ffNodeDict[ffNode['PeerMAC']] = {
                    'RawKey':None,
                    'Name':ffNode['PeerName'],
                    'Status':'?',
                    'last_online':0,
                    'Clients':0,
                    'Region':'??',
                    'DestSeg':99,
                    'oldGluon':'?',
                    'Segment':int(ffNode['SegDir'][3:]),
                    'SegMode':ffNode['SegMode'],
                    'KeyDir':ffNode['SegDir'],
                    'KeyFile':KeyIndex,
                    'FastdKey':ffNode['PeerKey'],
                    'InCloud':0,
                    'Neighbours':[]
                }

                self.MAC2NodeIDDict[ffNode['PeerMAC']] = ffNode['PeerMAC']
                self.__AddGluonMACs(ffNode['PeerMAC'],ffNode['VpnMAC'])

                if ffNode['VpnMAC'] != '':
                    print('!! New Node:      ',ffNode['SegDir'],'/',ffNode['PeerMAC'],'=',ffNode['PeerName'].encode('utf-8'))

            else:   # update existing node
                self.ffNodeDict[ffNode['PeerMAC']]['SegMode']  = ffNode['SegMode']
                self.ffNodeDict[ffNode['PeerMAC']]['KeyDir']   = ffNode['SegDir']
                self.ffNodeDict[ffNode['PeerMAC']]['KeyFile']  = KeyIndex
                self.ffNodeDict[ffNode['PeerMAC']]['FastdKey'] = ffNode['PeerKey']

            if ffNode['VpnMAC'] != '':
                if self.ffNodeDict[ffNode['PeerMAC']]['Status'] == '?':
                    print('!! Node is alive: ',ffNode['SegDir'],'/',ffNode['VpnMAC'],'->',ffNode['PeerMAC'],'=',ffNode['PeerName'].encode('utf-8'))
                elif self.ffNodeDict[ffNode['PeerMAC']]['Status'] != 'V':
                    print('++ Node is online:',ffNode['SegDir'],'/',ffNode['VpnMAC'],'->',ffNode['PeerMAC'],'=',ffNode['PeerName'].encode('utf-8'))

                self.ffNodeDict[ffNode['PeerMAC']]['Segment'] = int(ffNode['SegDir'][3:])
                self.ffNodeDict[ffNode['PeerMAC']]['Status'] = 'V'

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



    #==============================================================================
    # Method "UpdateStatistikDB"
    #
    #   Write updates Statistik-json
    #==============================================================================
    def UpdateStatistikDB(self,Path):

        print('Update Statistik-DB ...')

        StatisticsJsonName = os.path.join(Path,StatFileName)

        for ffNodeMAC in self.ffNodeDict.keys():
            if ((self.ffNodeDict[ffNodeMAC]['Status'] in OnlineStates) and
                (self.ffNodeDict[ffNodeMAC]['Segment'] is not None)):

                if self.ffNodeDict[ffNodeMAC]['Segment'] not in self.SegmentLoadDict:
                    self.SegmentLoadDict[str(self.ffNodeDict[ffNodeMAC]['Segment'])] = { 'Sum':0, 'Count':1 }

                self.SegmentLoadDict[str(self.ffNodeDict[ffNodeMAC]['Segment'])]['Sum'] += self.ffNodeDict[ffNodeMAC]['Clients'] + 1

        try:
            LockFile = open('/tmp/.SegStatistics.lock', mode='w+')
            fcntl.lockf(LockFile,fcntl.LOCK_EX)

            if os.path.exists(StatisticsJsonName):
                StatisticsJsonFile = open(StatisticsJsonName, mode='r')
                StatisticsJsonDict = json.load(StatisticsJsonFile)
                StatisticsJsonFile.close()

                for Segment in StatisticsJsonDict.keys():
                    if not Segment in self.SegmentLoadDict:
                        self.SegmentLoadDict[Segment] = { 'Sum':StatisticsJsonDict[Segment]['Sum'], 'Count':StatisticsJsonDict[Segment]['Count'] }
                    else:
                        self.SegmentLoadDict[Segment]['Sum']   += StatisticsJsonDict[Segment]['Sum']
                        self.SegmentLoadDict[Segment]['Count'] += StatisticsJsonDict[Segment]['Count']

                    if self.SegmentLoadDict[Segment]['Count'] > MaxStatisticsData:
                        self.SegmentLoadDict[Segment]['Sum']   -= int(CurrentSegStatistics[Segment]['Sum'] / CurrentSegStatistics[Segment]['Count'])
                        self.SegmentLoadDict[Segment]['Count'] -= 1

            print('Writing Statistik-DB as json-File ...')

            StatisticsJsonFile = open(StatisticsJsonName, mode='w')
            json.dump(self.SegmentLoadDict,StatisticsJsonFile)
            StatisticsJsonFile.close()

        except:
            self.__alert('\n!! Error on Updating Statistics Databases as json-File!')

        finally:
            fcntl.lockf(LockFile,fcntl.LOCK_UN)
            LockFile.close()

        print('... done.\n')
        return
