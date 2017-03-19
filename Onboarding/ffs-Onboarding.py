#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  ffs-Onboarding.py                                                                      #
#                                                                                         #
#  Automatically registering unknown Nodes, and updating existing but changed Nodes.      #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#      --pid       = fastd-PID                                                            #
#      --fastd     = fastd-Interface (e.g. vpnWW)                                         #
#      --batman    = batman-Interface (e.g. batWW)                                        #
#      --peerkey   = fastd-Key from Peer                                                  #
#      --gitrepo   = Git Repository with KeyFiles                                         #
#      --data      = Path to Databases                                                    #
#      --blacklist = Path to Blacklisting Files                                           #
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
import psutil
import signal
import time
import datetime
import socket

import git
import smtplib

from email.mime.text import MIMEText

import dns.resolver
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.update

from dns.rdataclass import *
from dns.rdatatype import *

import urllib.request
import json
import re
import hashlib
import fcntl
import argparse
import overpy

from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
from glob import glob


#----- Needed Data-Files -----
AccountFileName = '.Accounts.json'
StatFileName    = 'SegStatistics.json'
ZipTableName    = 'ZIP2GPS_DE.json'    # Data merged from OpenStreetMap and OpenGeoDB


#----- Global Constants -----
SEGMENT_FALLBACK = 5

SEGASSIGN_DOMAIN = 'segassign.freifunk-stuttgart.de'
SEGASSIGN_PREFIX = '2001:2:0:711::'

ZipTemplate      = re.compile('^[0-9]{5}$')
DnsNodeTemplate  = re.compile('^ffs(-[0-9a-f]{12}){2}$')
IPv6NodeTemplate = re.compile('^'+SEGASSIGN_PREFIX+'(([0-9a-f]{1,4}:){1,2})?[0-9]{1,2}$')

RegionDataFolder = 'regions'



#-----------------------------------------------------------------------
# Function "LoadAccounts"
#
#   Load Accounts from Accounts.json into AccountsDict
#
#-----------------------------------------------------------------------
def LoadAccounts(AccountFile):

    AccountsDict = None
    try:
        AccountJsonFile = open(AccountFile, mode='r')
        AccountsDict = json.load(AccountJsonFile)
        AccountJsonFile.close()

    except:
        print('\n!! Error on Reading Accounts json-File!\n')
        AccountsDict = None

    return AccountsDict



#-----------------------------------------------------------------------
# Function "__SendEmail"
#
#   Sending an Email
#
#-----------------------------------------------------------------------
def __SendEmail(Subject,MailBody,Account):

    if MailBody != '':
        try:
            Email = MIMEText(MailBody)

            Email['Subject'] = Subject
            Email['From']    = Account['Username']
            Email['To']      = Account['MailTo']
            Email['Bcc']     = Account['MailBCC']

            server = smtplib.SMTP(Account['Server'])
            server.starttls()
            server.login(Account['Username'],Account['Password'])
            server.send_message(Email)
            server.quit()
            print('\nEmail was sent to',Account['MailTo'])

        except:
            print('!! ERROR on sending Email to',Account['MailTo'])

    return



#-----------------------------------------------------------------------
# function "getFastdStatusSocket"
#
#-----------------------------------------------------------------------
def getFastdStatusSocket(pid):

    fastdSocket = ''

    try:
        p = psutil.Process(pid)
        connections = p.connections(kind='unix')
    except:
        pass
    else:
        for f in connections:
            if f.laddr.startswith("/var/run"):
                fastdSocket = f.laddr
                break

    return fastdSocket



#-----------------------------------------------------------------------
# function "getMeshMAC"
#
#-----------------------------------------------------------------------
def getMeshMAC(FastdStatusSocket):

    MeshMAC = None
    Retries = 5

    while MeshMAC is None and Retries > 0:
        Retries -= 1
        StatusData = ''
        time.sleep(2)

        try:
            FastdLiveStatus = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
            FastdLiveStatus.connect(FastdStatusSocket)
#            print('... Fastd-Socket connected, Retries =',Retries,'...')

            while True:
                tmpData = FastdLiveStatus.recv(1024*1024).decode('utf-8')
                if tmpData == '':
                    break;

                StatusData += tmpData

            FastdLiveStatus.close()
#            print('... Fastd-Data ->',StatusData)

            if StatusData != '':
                FastdStatusJson = json.loads(StatusData)

                if PeerKey in FastdStatusJson['peers']:
                    if FastdStatusJson['peers'][PeerKey]['connection'] is not None:
                        if 'mac_addresses' in FastdStatusJson['peers'][PeerKey]['connection']:
                            for MeshMAC in FastdStatusJson['peers'][PeerKey]['connection']['mac_addresses']:
                                break
        except:
            MeshMAC = None

    return MeshMAC



#-----------------------------------------------------------------------
# function "InfoFromGluonNodeinfoPage"
#
#    can be used on Gluon >= v2016.1
#
#  -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def InfoFromGluonNodeinfoPage(HttpIPv6):

    NodeInfoDict = None
    print('Connecting to http://['+HttpIPv6+']/cgi-bin/nodeinfo ...')

    try:
        NodeHTTP = urllib.request.urlopen('http://['+HttpIPv6+']/cgi-bin/nodeinfo',timeout=10)
        NodeJson = json.loads(NodeHTTP.read().decode('utf-8'))
        NodeHTTP.close()
    except:
        print('++ Error on loading /cgi-bin/nodeinfo')
        return None

    if 'node_id' in NodeJson and 'network' in NodeJson and 'hostname' in NodeJson:
        if 'mac' in NodeJson['network'] and 'addresses' in NodeJson['network']:
            if NodeJson['node_id'].strip() == NodeJson['network']['mac'].strip().replace(':',''):
                NodeInfoDict = {
                    'NodeType' : 'new',
                    'NodeID'   : NodeJson['node_id'].strip(),
                    'MAC'      : NodeJson['network']['mac'].strip(),
                    'Hostname' : NodeJson['hostname'].strip(),
                    'Segment'  : None,
                    'Location' : None
                }

                print('>>> NodeID   =',NodeInfoDict['NodeID'])
                print('>>> MAC      =',NodeInfoDict['MAC'])
                print('>>> Hostname =',NodeInfoDict['Hostname'].encode('utf-8'))

                if 'location' in NodeJson:
                    NodeInfoDict['Location'] = NodeJson['location']

                for NodeIPv6 in NodeJson['network']['addresses']:
                    print('>>> IPv6 =',NodeIPv6)
                    if NodeIPv6[0:12] == 'fd21:b4dc:4b' and NodeInfoDict['Segment'] is None:
                        if NodeIPv6[12:14] == '1e':
                             NodeInfoDict['Segment'] = 0
                        else:
                            NodeInfoDict['Segment'] = int(NodeIPv6[12:14])
#                        break
                print('>>> NodeInfo Segment =',NodeInfoDict['Segment'])

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "InfoFromGluonStatusPage"
#
#    must be used on Gluon < v2016.1
#
#  -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def InfoFromGluonStatusPage(HttpIPv6):

    NodeInfoDict = None
    NodeHTML = None
    print('Connecting to http://['+HttpIPv6+']/cgi-bin/status ...')

    try:
        NodeHTTP = urllib.request.urlopen('http://['+HttpIPv6+']/cgi-bin/status',timeout=10)
        NodeHTML = NodeHTTP.read().decode('utf-8')
        NodeHTTP.close()
    except:
        print('++ Error on loading /cgi-bin/status')
        return None

    NodeInfoDict = {
        'NodeType' : 'old',
        'NodeID'   : None,
        'MAC'      : None,
        'Hostname' : None,
        'Segment'  : None,
        'Location' : None
    }

    pStart = NodeHTML.find('<body><h1>')
    if pStart > 0:
        pStart += 10
        pStop = NodeHTML.find('</h1>',pStart)

        if pStop > pStart:
            NodeInfoDict['Hostname'] = NodeHTML[pStart:pStop].strip()
            print('>>> Hostname =',NodeInfoDict['Hostname'].encode('utf-8'))

    pStart = NodeHTML.find('link/ether ')
    if pStart > 0:
        pStart += 11
        print('>>> link/ether =',NodeHTML[pStart:pStart+20])
        pStop = NodeHTML.find(' brd ff:ff:ff:ff:ff:ff',pStart)

        if pStop >= pStart + 17:
            NodeInfoDict['MAC'] = NodeHTML[pStart:pStart+17]
            NodeInfoDict['NodeID'] =  NodeInfoDict['MAC'].replace(':','')
            print('>>> MAC =',NodeInfoDict['MAC'])

    pStart = NodeHTML.find('inet6 fd21:b4dc:4b')
    if pStart > 0:
        pStart += 18
        pStop = NodeHTML.find('/64 scope global',pStart)

        if pStop > pStart + 2:
            if NodeHTML[pStart:pStart+2] == '1e':
                NodeInfoDict['Segment'] = 0
            else:
                NodeInfoDict['Segment'] = int(NodeHTML[pStart:pStart+2])

            print('>>> StatusInfo Segment =',NodeInfoDict['Segment'])

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "getNodeInfos"
#
#-----------------------------------------------------------------------
def getNodeInfos(HttpIPv6):

    NodeInfoDict = None
    NodeHTML = None
    Retries = 3

    while NodeHTML is None and Retries > 0:
        time.sleep(1)
        print('Connecting to http://['+HttpIPv6+'] ...')
        Retries -= 1
        try:
            NodeHTTP = urllib.request.urlopen('http://['+HttpIPv6+']/',timeout=15)
            NodeHTML = NodeHTTP.read().decode('utf-8')
            NodeHTTP.close()
        except:
            NodeHTML = None
            pass

    if NodeHTML is not None:
        if NodeHTML.find('/cgi-bin/nodeinfo') > 0:
            print('... is new Gluon ...')
            NodeInfoDict = InfoFromGluonNodeinfoPage(HttpIPv6)
        elif  NodeHTML.find('/cgi-bin/status') > 0:
            print('... is old Gluon ...')
            NodeInfoDict = InfoFromGluonStatusPage(HttpIPv6)
        else:
            print('+++ unknown System!')
            NodeInfoDict =  None

        if NodeInfoDict is not None:
            if NodeInfoDict['NodeID'] is None or NodeInfoDict['MAC'] is None or NodeInfoDict['Hostname'] is None:
                NodeInfoDict = None
            elif len(NodeInfoDict['NodeID']) != 12 or NodeInfoDict['NodeID'] != NodeInfoDict['MAC'].replace(':',''):
                NodeInfoDict = None

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "GetDnsInfo"
#
#-----------------------------------------------------------------------
def GetDnsInfo(DnsServerName):

    print('... Loading DNS Info ...')
    DnsDataDict = None
    NodeCount = 0

    try:
        DnsResolver = dns.resolver.Resolver()
        DnsServerIP = DnsResolver.query('%s.' % (DnsServerName),'a')[0].to_text()
        DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,SEGASSIGN_DOMAIN))
    except:
        print('!! ERROR on fetching segassign DNS Zone!')
        DnsZone = None

    if DnsZone is not None:
        DnsDataDict = { 'NodeID':{}, 'KeyID':{} }

        for name, node in DnsZone.nodes.items():
            DnsNodeID = name.to_text().strip()

            if DnsNodeTemplate.match(DnsNodeID):
                NodeCount += 1
                ffNodeID  = DnsNodeID[4:16]
                ffNodeKey = DnsNodeID[17:]
                ffNodeSeg = None

                for rds in node.rdatasets:
                    if rds.rdtype == dns.rdatatype.AAAA and ffNodeSeg is None:
                        for r in rds:
                            IPv6 = r.to_text().strip()

                            if IPv6NodeTemplate.match(IPv6):
                                DnsNodeInfo = IPv6.split(':')
                                ffNodeSeg = int(DnsNodeInfo[-1])
                                break

                if ffNodeID in DnsDataDict['NodeID']:
                    print('!! Duplicate NodeID:',ffNodeID,'->',DnsDataDict['NodeID'][ffNodeID])
                else:
                    DnsDataDict['NodeID'][ffNodeID] = { 'KeyID':ffNodeKey, 'Segment':ffNodeSeg }

                if ffNodeKey in DnsDataDict['KeyID']:
                    print('!! Duplicate fastd Key:',ffNodeKey,'->',DnsDataDict['KeyID'][ffNodeKey])
                else:
                    DnsDataDict['KeyID'][ffNodeKey] = ffNodeID

                if ffNodeSeg is None:
                    print('!! No Segment for NodeID:',ffNodeID,'->',DnsDataDict['NodeID'][ffNodeID])


        print('... DNS-Infos loaded:',NodeCount)

    return DnsDataDict



#-----------------------------------------------------------------------
# function "ActivateBatman"
#
#-----------------------------------------------------------------------
def ActivateBatman(BatmanIF,FastdIF):

    print('... Activating Batman ...')
    Retries = 10
    NeighborMAC = None

    try:
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','add',FastdIF])
        subprocess.run(['/sbin/ip','link','set','dev',BatmanIF,'up'])
        print('... Batman Interface',BatmanIF,'is up ...')
    except:
        print('++ Cannot bring up',BatmanIF,'!')
    else:
        while(Retries > 0):
            Retries -= 1
            time.sleep(2)

            try:
                BatctlN = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'n'], stdout=subprocess.PIPE)
                BatctlResult = BatctlN.stdout.decode('utf-8')

                for NeighborInfo in BatctlResult.split('\n'):
                    NeighborDetails = NeighborInfo.split()
                    if NeighborDetails[0] == FastdIF:
                        NeighborMAC = NeighborDetails[1]
                        Retries = 0
                        break
            except:
                NeighborMAC = None

    return NeighborMAC



#-----------------------------------------------------------------------
# function "DeactivateBatman"
#
#-----------------------------------------------------------------------
def DeactivateBatman(BatmanIF,FastdIF):

    print('... Deactivating Batman ...')

    try:
        subprocess.run(['/sbin/ip','link','set','dev',BatmanIF,'down'])
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','del',FastdIF])
        print('... Batman Interface',BatmanIF,'is down.')
    except:
        print('++ Cannot shut down',BatmanIF,'!')
        pass

    return



#-----------------------------------------------------------------------
# function "GenerateGluonMACsOld(MainMAC)"
#
#   Get all related MACs based on Primary MAC for Gluon <= 2016.1.x
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
def GenerateGluonMACsOld(MainMAC):

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
# function "GenerateGluonMACsNew(MainMAC)"
#
#   Get all related MACs based on Primary MAC for Gluon >= 2016.2.x
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
def GenerateGluonMACsNew(MainMAC):

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



#-----------------------------------------------------------------------
# function "GetBatmanNodeMAC"
#
#   Get Node's main MAC by Batman Global Translation Table
#
#-----------------------------------------------------------------------
def GetBatmanNodeMAC(BatmanIF,BatmanVpnMAC):

    print('Find Primary MAC in Batman TG:',BatmanIF,'/',BatmanVpnMAC)
    GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[5-9]))(:[0-9a-f]{2}){3}')
    MacAdrTemplate    = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
    Retries           = 15
    NodeMainMAC       = None

    BatctlCmd = ('/usr/sbin/batctl -m %s tg' % (BatmanIF)).split()

    while Retries > 0 and NodeMainMAC is None:
        Retries -= 1
        time.sleep(2)

        try:
            BatctlTG = subprocess.run(BatctlCmd, stdout=subprocess.PIPE)
            BatctlResult = BatctlTG.stdout.decode('utf-8')
#            print('>>>',BatctlResult)

            for BatctlLine in BatctlResult.split('\n'):
                BatctlInfo = BatctlLine.replace('(',' ').replace(')',' ').split()
                #----- BatctlInfo[1] = Client-MAC  /  BatctlInfo[5] = Node-Tunnel-MAC -----

                if len(BatctlInfo) == 9 and MacAdrTemplate.match(BatctlInfo[1]) and not GwAllMacTemplate.match(BatctlInfo[1]):
                    if BatctlInfo[2] == '-1' and MacAdrTemplate.match(BatctlInfo[5]) and not GwAllMacTemplate.match(BatctlInfo[5]):

                        if ((BatctlInfo[1][:1] == BatctlInfo[5][:1] and BatctlInfo[1][9:] == BatctlInfo[5][9:]) and
                            (BatctlInfo[5][:1] == BatmanVpnMAC[:1]  and BatctlInfo[5][9:] == BatmanVpnMAC[9:])):  # old MAC schema
                            print('>>> is old schema:',BatmanVpnMAC,'=',BatctlInfo[1],'->',BatctlInfo[5])
                            BatmanMacList = GenerateGluonMACsOld(BatctlInfo[1])
#                            print('>>> Old MacList:',BatmanMacList)
                        elif BatctlInfo[5][:16] == BatmanVpnMAC[:16]:  # new MAC schema
                            print('>>> is new schema:', BatmanVpnMAC,'=',BatctlInfo[1],'->',BatctlInfo[5])
                            BatmanMacList = GenerateGluonMACsNew(BatctlInfo[1])
#                            print('>>> New MacList:',BatmanMacList)
                        else:
                            BatmanMacList = []

                        if BatctlInfo[5] in BatmanMacList and BatmanVpnMAC in BatmanMacList:
                            NodeMainMAC = BatctlInfo[1]
                            print('>>> Batman TG =',BatctlLine)
                            break

        except:
            print('++ ERROR accessing batman:',BatctlCmd)
            NodeMainMAC = None

    print('... Batman Primary MAC =',NodeMainMAC)
    return NodeMainMAC



#-----------------------------------------------------------------------
# function "getBatmanSegment"
#
#-----------------------------------------------------------------------
def getBatmanSegment(BatmanIF,FastdIF):

    print('... get Segment via Batman Gateways ...')
    Retries = 15
    BatSeg = None

    while Retries > 0 and BatSeg is None:
        Retries -= 1
        time.sleep(2)

        try:
            BatctlGwl = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'gwl'], stdout=subprocess.PIPE)
            gwl = BatctlGwl.stdout.decode('utf-8')

            for Gateway in gwl.split('\n'):
                if Gateway[3:10] == '02:00:3':
                    BatSeg = int(Gateway[12:14])
                    break
                elif Gateway[3:12] == '02:00:0a:':
                    BatSeg = int(Gateway[15:17])
                    break
        except:
            print('++ ERROR accessing',BatmanIF)
            BatSeg = None

    print('... Batman Segment =',BatSeg)
    return BatSeg



#-------------------------------------------------------------
# function "__SetupZipData"
#
#     Load ZIP File of OpenGeoDB Project
#
#-------------------------------------------------------------
def __SetupZipData(Path):

    print('... Setting up ZIP Data ...')
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
# function "__SetupRegionData"
#
#     Load Region Json Files and setup polygons
#
#-------------------------------------------------------------
def __SetupRegionData(Path):

    print('... Setting up Region Data ...')

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

    print('... Region Areas loaded:',RegionCount)
    return RegionDict



#-----------------------------------------------------------------------
# function "GetSegmentFromGPS"
#
#   Get Segment from Position (GPS Coordinate)
#-----------------------------------------------------------------------
def GetSegmentFromGPS(lat,lon,RegionDict):

    print('... Get Segment from GPS Data ...')

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
            print('++ Invalid Location:',lat,'|',lon)

    return Segment



#-----------------------------------------------------------------------
# function "GetGeoSegment"
#
#   Get Segment from Regions
#-----------------------------------------------------------------------
def GetGeoSegment(Location,RegionDataPath):

    print('Get Segment from Position ...',Location)

    RegionDict  = __SetupRegionData(RegionDataPath)
    Segment = None

    if RegionDict is None:
        print('!! No Region Data available !!!')
    else:
        if 'latitude' in Location and 'longitude' in Location:
            lat = Location['latitude']
            lon = Location['longitude']

            if lat < lon:
                lat = Location['longitude']
                lon = Location['latitude']

            Segment = GetSegmentFromGPS(lat,lon,RegionDict)

        if 'zip' in Location:
            ZipCode = str(Location['zip'])[:5]
            ZipSegment = None
            print('... Checking ZIP-Code',ZipCode)

            if ZipTemplate.match(ZipCode):
                Zip2PosDict = __SetupZipData(RegionDataPath)

                if Zip2PosDict is not None:
                    if ZipCode in Zip2PosDict:
                        lat = float(Zip2PosDict[ZipCode]['lat'])
                        lon = float(Zip2PosDict[ZipCode]['lon'])
                        ZipSegment = GetSegmentFromGPS(lat,lon,RegionDict)

                if ZipSegment is None:  # Fallback to OpenStreetMap online request
                    lat = 0.0
                    lon = 0.0

                    try:
                        api = overpy.Overpass()
                        query = 'rel[postal_code="%s"];out center;' % (ZipCode)
                        result = api.query(query)

                        for relation in result.relations:
                            lat = relation.center_lat
                            lon = relation.center_lon
                            ZipSegment = GetSegmentFromGPS(lat,lon,RegionDict)
                            break
                    except:
                        ZipSegment = None

                print('>>> GeoSegment / ZipSegment =',Segment,'/',ZipSegment)

                if Segment is not None:
                    if ZipSegment is not None and ZipSegment != Segment:
                        print('!! Segment Mismatch Geo <> ZIP:',Segment,'<>',ZipSegment)
                elif ZipSegment is not None:
                    Segment = ZipSegment
                    print('++ Segment set by ZIP-Code:',Segment)
                else:
                    print('... unknown ZIP-Code:',ZipCode)
            else:
                print('... invalid ZIP-Code Format:',ZipCode)

    return Segment



#-----------------------------------------------------------------------
# function "GetDefaultSegment"
#
#-----------------------------------------------------------------------
def GetDefaultSegment(StatisticsJsonName):

    MinWeight  = 9999
    DefaultSeg = None

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

        for JsonSegIdx in StatisticsJsonDict.keys():
            Segment = int(JsonSegIdx)

            if Segment > 0  and Segment != 6 and Segment < 9:  #....................................... must be changed later !!
                if StatisticsJsonDict[JsonSegIdx]['Count'] != '0':
                    SegWeight = int(int(StatisticsJsonDict[JsonSegIdx]['Sum']) / int(StatisticsJsonDict[JsonSegIdx]['Count']))

                    if SegWeight < MinWeight:
                        MinWeight  = SegWeight
                        DefaultSeg = Segment

    except:
        print('++ Using Fallback Segment because statistics not available.')
        DefaultSeg = SEGMENT_FALLBACK

    finally:
        fcntl.lockf(LockFile,fcntl.LOCK_UN)
        LockFile.close()

    print('... Default Segment =',DefaultSeg)
    return DefaultSeg



#-----------------------------------------------------------------------
# function "WriteNodeKeyFile"
#
#-----------------------------------------------------------------------
def WriteNodeKeyFile(KeyFileName,NodeInfo,PeerKey):

    print('... Writing KeyFile:',KeyFileName)

    KeyFile = open(KeyFileName, mode='w')
    KeyFile.write('#MAC: %s\n#Hostname: %s\nkey \"%s\";\n' % (NodeInfo['MAC'],NodeInfo['Hostname'],PeerKey))
    KeyFile.close()
    print('... done.')
    return



#-----------------------------------------------------------------------
# function "RegisterNode"
#
#   Actions:
#     NEW_KEY
#     NEW_MAC
#     NEW_NODE
#     CHANGE_SEGMENT
#
#-----------------------------------------------------------------------
def RegisterNode(Action, NodeInfo, PeerKey, oldNodeID, oldKeyID, oldSegment, GitPath, AccountsDict):

    DnsKeyRing = None
    DnsUpdate  = None
    isOK       = True

    NewPeerDnsName = 'ffs-%s-%s' % (NodeInfo['NodeID'],PeerKey[:12])
    NewPeerDnsIPv6 = '%s%d' % (SEGASSIGN_PREFIX,NodeInfo['Segment'])
    NewPeerFile    = 'vpn%02d/peers/ffs-%s' % (NodeInfo['Segment'],NodeInfo['NodeID'])
    print('>>> New Peer Data:', NewPeerDnsName, '=', NewPeerDnsIPv6, '->', NewPeerFile,)

    try:
        #----- Synchronizing Git Acccess -----
        GitLockName = os.path.join('/tmp','.'+os.path.basename(GitPath)+'.lock')
#        print('>>> GitLockName:',GitLockName)
        LockFile = open(GitLockName, mode='w+')
        fcntl.lockf(LockFile,fcntl.LOCK_EX)
#        print('>>> lock is set.')

        #----- Handling registration -----
        DnsResolver = dns.resolver.Resolver()
        DnsServerIP = DnsResolver.query('%s.' % (AccountsDict['DNS']['Server']),'a')[0].to_text()
#        print('... DNS-Server IP =',DnsServerIP)

        DnsKeyRing = dns.tsigkeyring.from_text( {AccountsDict['DNS']['ID'] : AccountsDict['DNS']['Key']} )
        DnsUpdate  = dns.update.Update(SEGASSIGN_DOMAIN, keyring = DnsKeyRing, keyname = AccountsDict['DNS']['ID'], keyalgorithm = 'hmac-sha512')

        GitRepo   = git.Repo(GitPath)
        GitIndex  = GitRepo.index
        GitOrigin = GitRepo.remotes.origin

        if GitRepo.is_dirty() or len(GitRepo.untracked_files) > 0 or DnsUpdate is None:
            print('!! The Git Repository and/or DNS are not clean - cannot register Node!')
            DnsUpdate = None

        elif Action == 'NEW_KEY':
            print('*** New Key for existing Node: vpn%02d / %s = %s -> %s...' % (NodeInfo['Segment'],NodeInfo['MAC'],NodeInfo['Hostname'].encode('utf-8'),PeerKey[:12]))
            WriteNodeKeyFile(os.path.join(GitPath,NewPeerFile),NodeInfo,PeerKey)
#            print('>>> File written:',os.path.join(GitPath,NewPeerFile))
            OldPeerDnsName = 'ffs-%s-%s' % (NodeInfo['NodeID'],oldKeyID)
            DnsUpdate.delete(OldPeerDnsName,'AAAA')
            DnsUpdate.add(NewPeerDnsName,300,'AAAA',NewPeerDnsIPv6)
#            print('>>> DNS update done.')

            GitIndex.add([NewPeerFile])
#            print('>>> Git add of modified file done.')

        elif Action == 'NEW_MAC':
            print('*** New MAC with existing Key: vpn%02d / %s -> vpn%02d / %s = %s (%s...)' % (oldSegment,oldNodeID,NodeInfo['Segment'],NodeInfo['MAC'],NodeInfo['Hostname'].encode('utf-8'),PeerKey[:12]))
            WriteNodeKeyFile(os.path.join(GitPath,NewPeerFile),NodeInfo,PeerKey)
            OldPeerDnsName = 'ffs-%s-%s' % (oldNodeID,PeerKey[:12])
            DnsUpdate.delete(OldPeerDnsName,'AAAA')
            DnsUpdate.add(NewPeerDnsName, 300,'AAAA',NewPeerDnsIPv6)
#            print('>>> DNS update done.')

            OldPeerFile = 'vpn%02d/peers/ffs-%s' % (oldSegment,oldNodeID)
            GitIndex.remove([OldPeerFile])
#            print('>>> Git remove of old file done.')
            os.rename(os.path.join(GitPath,OldPeerFile), os.path.join(GitPath,NewPeerFile))
            GitIndex.add([NewPeerFile])
#            print('>>> Git add of modified file done.')

        elif Action == 'NEW_NODE':
            print('*** New Node: vpn%02d / ffs-%s = %s (%s...)' % (NodeInfo['Segment'],NodeInfo['NodeID'],NodeInfo['Hostname'].encode('utf-8'),PeerKey[:12]))
            WriteNodeKeyFile(os.path.join(GitPath,NewPeerFile), NodeInfo, PeerKey)
#            print('>>> File written:',os.path.join(GitPath,NewPeerFile))
            DnsUpdate.add(NewPeerDnsName, 300, 'AAAA',NewPeerDnsIPv6)
#            print('>>> DNS add done.')

            GitIndex.add([NewPeerFile])
#            print('>>> Git add of new file done.')

        elif Action == 'CHANGE_SEGMENT':
            print('!!! New Segment for existing Node: vpn%02d / %s = %s -> vpn02d' % (oldSegment,NodeInfo['MAC'],NodeInfo['Hostname'].encode('utf-8'),NodeInfo['Segment']))
            DnsUpdate.replace(NewPeerDnsName, 300, 'AAAA',NewPeerDnsIPv6)

            OldPeerFile = 'vpn%02d/peers/ffs-%s' % (oldSegment,NodeInfo['NodeID'])
            GitIndex.remove([OldPeerFile])
            os.rename(os.path.join(GitPath,OldPeerFile), os.path.join(GitPath,NewPeerFile))
            GitIndex.add([NewPeerFile])

        else:
            print('!!! Invalid Action:',Action)
            DnsUpdate = None

        if DnsUpdate is not None:
            dns.query.tcp(DnsUpdate,DnsServerIP)

            GitIndex.commit('Onboarding (%s) of Peer \"%s\" in Segment %02d' % (Action,NodeInfo['Hostname'],NodeInfo['Segment']))
            GitOrigin.config_writer.set('url',AccountsDict['Git']['URL'])
#            print('... doing Git pull ...')
            GitOrigin.pull()
            print('... doing Git push ...')
            GitOrigin.push()

            MailBody = 'Automatic Onboarding (%s) in Segment %02d:\n\n#MAC: %s\n#Hostname: %s\nkey \"%s\";\n' % (Action,NodeInfo['Segment'],NodeInfo['MAC'],NodeInfo['Hostname'],PeerKey)
            print(MailBody)

            __SendEmail('Onboarding of Node %s by ffs-Monitor' % (NodeInfo['Hostname']),MailBody,AccountsDict['KeyMail'])
        else:
            print('!!! ERROR - DnsUpdate is None:',Action)

    except:
        print('!!! ERROR on registering Node:',Action)
        isOK = False

    finally:
        del GitOrigin
        del GitIndex
        del GitRepo

        fcntl.lockf(LockFile,fcntl.LOCK_UN)
        LockFile.close()

    return isOK



#-----------------------------------------------------------------------
# function "setBlacklistFile"
#
#-----------------------------------------------------------------------
def setBlacklistFile(BlacklistFile):

    try:
        OutFile = open(BlacklistFile, mode='w')
        OutFile.write('%d\n' % (int(time.time())))
        OutFile.close()
        print('... Blacklisting set ...')
    except:
        print('++ ERROR on Blacklisting!')
        pass

    return



#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
parser = argparse.ArgumentParser(description='Add or Modify Freifunk Node Registration')
parser.add_argument('--pid', dest='FASTDPID', action='store', required=True, help='Fastd PID')
parser.add_argument('--fastd', dest='VPNIF', action='store', required=True, help='Fastd Interface = Segment')
parser.add_argument('--batman', dest='BATIF', action='store', required=True, help='Batman Interface')
parser.add_argument('--peerkey', dest='PEERKEY', action='store', required=True, help='Fastd PeerKey')
parser.add_argument('--gitrepo', dest='GITREPO', action='store', required=True, help='Git Repository with KeyFiles')
parser.add_argument('--data', dest='DATAPATH', action='store', required=True, help='Path to Databases')
parser.add_argument('--blacklist', dest='BLACKLIST', action='store', required=True, help='Blacklist Folder')

args = parser.parse_args()
PeerKey  = args.PEERKEY
FastdPID = int(args.FASTDPID)
RetCode  = 0

print('Onboarding of',PeerKey,'started with PID =',psutil.Process().pid,'...')

#if True:
if not os.path.exists(args.BLACKLIST+'/'+args.PEERKEY):
    setBlacklistFile(os.path.join(args.BLACKLIST,PeerKey))

    print('... loading Account Data ...')
    AccountsDict = LoadAccounts(os.path.join(args.DATAPATH,AccountFileName))  # All needed Accounts for Accessing resricted Data

    print('... getting Fastd Status Socket ...')
    FastdStatusSocket = getFastdStatusSocket(FastdPID)

    if os.path.exists(FastdStatusSocket) and AccountsDict is not None:

        print('... getting MeshMAC from fastd status ...')
        MeshMAC = getMeshMAC(FastdStatusSocket)

        if MeshMAC is not None:
            print('... MeshMAC =',MeshMAC)

            BatmanVpnMAC = ActivateBatman(args.BATIF,args.VPNIF)

            if BatmanVpnMAC is not None and BatmanVpnMAC == MeshMAC:
                print('... Batman and fastd are matching:',BatmanVpnMAC)
                NodeIPv6 = 'fe80::' + hex(int(MeshMAC[0:2],16) ^ 0x02)[2:] + MeshMAC[3:8]+'ff:fe'+MeshMAC[9:14]+MeshMAC[15:17]+'%'+args.VPNIF
                NodeInfo = getNodeInfos(NodeIPv6)                       # Data from status page of Node via HTTP
                PeerMAC  = GetBatmanNodeMAC(args.BATIF,BatmanVpnMAC)    # Node's main MAC from Batman Global Translation Table

                if NodeInfo is not None:
                    if PeerMAC is not None and PeerMAC != NodeInfo['MAC']:
                        print('!! PeerMAC mismatch Status Page <> Batman:',NodeInfo['MAC'],PeerMAC)
                        NodeInfo = None

                elif PeerMAC is not None:    # No status page -> Fallback to batman
                    NodeInfo    = {
                        'NodeType' : 'unknown',
                        'NodeID'   : PeerMAC.replace(':',''),
                        'MAC'      : PeerMAC,
                        'Hostname' : 'ffs-'+PeerMAC.replace(':',''),
                        'Segment'  : None,
                        'Location' : None
                    }

                    print('++ Statuspage not available -> Fallback to Batman:',PeerMAC,'=',NodeInfo['Hostname'].encode('utf-8'))


                if NodeInfo is not None:

                    if NodeInfo['Segment'] is None:
                        NodeInfo['Segment'] = getBatmanSegment(args.BATIF,args.VPNIF)    # segment from batman gateway list
                        print('++ No Segment on Statuspage -> Fallback to Batman:',NodeInfo['MAC'],'=',NodeInfo['Hostname'].encode('utf-8'),'->',NodeInfo['Segment'])

                    if NodeInfo['Segment'] is None:
                        if NodeInfo['NodeType'] == 'old':
                            NodeInfo['Segment'] = 0
                            print('>>> Old Gluon must be in Segment 0 = Legacy')
                        elif NodeInfo['Location'] is not None:
                            NodeInfo['Segment'] = GetGeoSegment(NodeInfo['Location'],os.path.join(args.DATAPATH,RegionDataFolder))
                            print('>>> GeoSegment =',NodeInfo['Segment'])

                    PeerFile = 'ffs-'+NodeInfo['NodeID']
                    DnsDataDict = GetDnsInfo(AccountsDict['DNS']['Server'])

                    if DnsDataDict is not None:
                        if NodeInfo['NodeID'] in DnsDataDict['NodeID']:
                            KeyID = DnsDataDict['NodeID'][NodeInfo['NodeID']]['KeyID']

                            if KeyID == PeerKey[:12]:    # ... This Node is already registered in DNS
                                DnsSegment = DnsDataDict['NodeID'][NodeInfo['NodeID']]['Segment']
                                print('>>> Segment from DNS / Node =',DnsSegment,'/',NodeInfo['Segment'])

                                if DnsSegment is not None:
                                    if NodeInfo['Segment'] is not None and NodeInfo['Segment'] != DnsSegment:
                                        print('!! Node must be moved to other Segment: vpn%02d / %s -> vpn%02d\n' % (DnsSegment,PeerFile,NodeInfo['Segment']))

                                        if not RegisterNode('CHANGE_SEGMENT', NodeInfo, PeerKey, None, None, DnsSegment, args.GITREPO, AccountsDict):
                                            RetCode = 1

                                    elif NodeInfo['NodeType'] == 'old' and DnsSegment != 0:
                                        print('!! Old Node is meshing in new Cloud: vpn%02d / %s\n' % (DnsSegment,PeerFile))
                                    else:
                                        print('++ Node is already registered: vpn%02d / %s\n' % (DnsSegment,PeerFile))
                                else:
                                    print('!! Invalid DNS-Entry for Node: %s-%s\n' % (PeerFile,PeerKey[:12]))

                            else:    # ... New Key for existing Node Hardware
                                print('!! New Key for existing Node:',PeerFile,'/',NodeInfo['MAC'],'=',NodeInfo['Hostname'],'->',KeyID+'...')

                                if not RegisterNode('NEW_KEY', NodeInfo, PeerKey, None, KeyID, None, args.GITREPO, AccountsDict):
                                    RetCode = 1


                        else:    # NodeID is not registered ...
                            if PeerKey[:12] in DnsDataDict['KeyID']:    # Key is already used ...
                                oldNodeID = DnsDataDict['KeyID'][PeerKey[:12]]
                                oldSegment  = DnsDataDict['NodeID'][oldNodeID]['Segment']
                                print('!! Key is already in use (old -> new): vpn%02d / ffs-%s -> vpn%02d / %s = %s' % (oldSegment,oldNodeID, NodeInfo['Segment'],PeerFile,NodeInfo['Hostname']))

                                if not RegisterNode('NEW_MAC', NodeInfo, PeerKey, oldNodeID, PeerKey[:12], oldSegment, args.GITREPO, AccountsDict):
                                    RetCode = 1

                            else:    # ... is new Node ...
                                if NodeInfo['Segment'] is None:
                                    NodeInfo['Segment'] = GetDefaultSegment(os.path.join(args.DATAPATH,StatFileName))
                                    print('>>> Default Segment =',NodeInfo['Segment'])

                                if not RegisterNode('NEW_NODE', NodeInfo, PeerKey, None, None, None, args.GITREPO, AccountsDict):
                                    RetCode = 1

                    else:
                        print('!! ERROR: No DNS-Data available !!')

                else:
                    print('++ Node status information not available or inconsistent!')
            else:
                print('++ Node VPN MAC via Batman <> via FastD:',BatmanVpnMAC,'<>',MeshMAC)

            DeactivateBatman(args.BATIF,args.VPNIF)

        else:
            print('++ MeshMAC (or KeyDataDict) is not available!',MeshMAC)

    else:
        print('!! ERROR: Accounts or Fastd Status Socket not available!')

else:
    print('!! ERROR: Node is blacklisted:',PeerKey)


os.kill(FastdPID,signal.SIGUSR2)    # reset fastd connections

exit(RetCode)
