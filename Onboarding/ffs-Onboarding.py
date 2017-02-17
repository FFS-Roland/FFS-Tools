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
#      --json      = Path to json files with data of nodes                                #
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
import dns.resolver
import urllib.request
import json
import re
import hashlib
import fcntl
import argparse


#----- Json-File with needed Accounts -----
AccountFileName = '.Accounts.json'


#----- Global Constants -----
NEXTNODE_PREFIX  = 'fd21:711::'
SEGASSIGN_DOMAIN = '.segassign.freifunk-stuttgart.de.'
SEGASSIGN_PREFIX = '2001:2:0:711::'



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
                    'Segment'  : None
                }

                print('>>> NodeID   =',NodeInfoDict['NodeID'])
                print('>>> MAC      =',NodeInfoDict['MAC'])
                print('>>> Hostname =',NodeInfoDict['Hostname'].encode('utf-8'))

                for NodeIPv6 in NodeJson['network']['addresses']:
                    print('>>> IPv6 =',NodeIPv6)
                    if NodeIPv6[0:12] == 'fd21:b4dc:4b' and NodeInfoDict['Segment'] is None:
                        if NodeIPv6[12:14] == '1e':
                             NodeInfoDict['Segment'] = 'vpn00'
                        else:
                            NodeInfoDict['Segment'] = 'vpn'+NodeIPv6[12:14]
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
        'Segment'  : None
    }

    pStart = NodeHTML.find('<body><h1>')
    if pStart > 0:
        pStart += 10
        pStop = NodeHTML.find('</h1>',pStart)
        if pStop > pStart:
            NodeInfoDict['Hostname'] = NodeHTML[pStart:pStop].strip()
            print('>>> Hostname =',NodeHTML[pStart:pStop].encode('utf-8'))

    pStart = NodeHTML.find('link/ether ')
    if pStart > 0:
        pStart += 11
        print('>>> link/ether =',NodeHTML[pStart:pStart+20])
        pStop = NodeHTML.find(' brd ff:ff:ff:ff:ff:ff',pStart)
        print(pStart,pStop)
        if pStop >= pStart + 17:
            NodeInfoDict['MAC'] = NodeHTML[pStart:pStart+17]
            NodeInfoDict['NodeID'] =  NodeInfoDict['MAC'].replace(':','')
            print('>>> MAC =',NodeHTML[pStart:pStop])

    pStart = NodeHTML.find('inet6 fd21:b4dc:4b')
    if pStart > 0:
        pStart += 18
        pStop = NodeHTML.find('/64 scope global',pStart)
        if pStop > pStart + 2:
            if NodeHTML[pStart:pStart+2] == '1e':
                NodeInfoDict['Segment'] = 'vpn00'

        print('>>> StatusInfo Segment =',NodeHTML[pStart:pStop])

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
            elif len(NodeInfoDict['NodeID']) != 12 or  NodeInfoDict['NodeID'] != NodeInfoDict['MAC'].replace(':',''):
                NodeInfoDict = None

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "checkDNS"
#
#-----------------------------------------------------------------------
def checkDNS(NodeID,DnsServer):

    SegFromDNS = None
    DnsResolver = dns.resolver.Resolver()
    DnsServerIP = DnsResolver.query('%s.'%(DnsServer),'a')[0].to_text()

    DnsResolver.nameservers = [ DnsServerIP ]

    Hostname = NodeID + SEGASSIGN_DOMAIN
    print('DNS Query =',Hostname)

    try:
        aaaaRecs = DnsResolver.query(Hostname,'aaaa')

        for IPv6 in aaaaRecs:
            if IPv6.to_text()[:14] == SEGASSIGN_PREFIX:
                SegFromDNS = 'vpn'+IPv6.to_text()[14:].zfill(2)

    except:
        SegFromDNS = None

    return SegFromDNS



#-----------------------------------------------------------------------
# function "LoadKeyData"
#
#-----------------------------------------------------------------------
def LoadKeyData(Path):

    KeyDataDict = None

    try:
        LockFile = open('/tmp/.ffsKeyData.lock', mode='w+')
        fcntl.lockf(LockFile,fcntl.LOCK_EX)

        KeyJsonFile = open(os.path.join(Path,'KeyData.json'), mode='r')
        KeyDataDict = json.load(KeyJsonFile)
        KeyJsonFile.close()

    except:
        print('\n!! Error on Reading Fastd Key Databas json-File!\n')
        KeyDataDict = None

    finally:
        fcntl.lockf(LockFile,fcntl.LOCK_UN)
        LockFile.close()

    return KeyDataDict



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
        print('... Batman Interface',BatmanIF,'is down ...')
    except:
        print('++ Cannot shut down',BatmanIF,'!')
        pass

    return



#-----------------------------------------------------------------------
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

    print('Querying Batman Info from',BatmanIF,'/',BatmanVpnMAC)
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
                    if MacAdrTemplate.match(BatctlInfo[5]) and not GwAllMacTemplate.match(BatctlInfo[5]) and  BatctlInfo[8] == '[....]':
                        if BatctlInfo[5][:16] == BatmanVpnMAC[:16]:  # new MAC schema
                            print('>>> is new schema:', BatmanVpnMAC,'=',BatctlInfo[1],'->',BatctlInfo[5])
                            BatmanMacList = GenerateGluonMACsNew(BatctlInfo[1])
#                            print('>>> New MacList:',BatmanMacList)
                        elif BatctlInfo[5][:2] == BatmanVpnMAC[:2] and BatctlInfo[5][9:] == BatmanVpnMAC[9:]:  # old MAC schema
                            print('>>> is old schema:',BatmanVpnMAC,'=',BatctlInfo[1],'->',BatctlInfo[5])
                            BatmanMacList = GenerateGluonMACsOld(BatctlInfo[1])
#                            print('>>> Old MacList:',BatmanMacList)
                        else:
                            BatmanMacList = []

                        if BatctlInfo[5] in BatmanMacList and BatmanVpnMAC in BatmanMacList:
                            NodeMainMAC = BatctlInfo[1]
                            print('>>> Batman TG =',BatctlLine)
                            break

        except:
            print('++ ERROR accessing batman:',BatctlCmd)
            NodeMainMAC = None

    print('... Node Main MAC =',NodeMainMAC)
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
                    BatSeg = 'vpn'+Gateway[12:14]
                    break
                elif Gateway[3:12] == '02:00:0a:':
                    BatSeg = 'vpn'+Gateway[15:17]
                    break
        except:
            print('++ ERROR accessing',BatmanIF)
            BatSeg = None

    print('... Batman Segment =',BatSeg)
    return BatSeg



#-----------------------------------------------------------------------
# function "__TestAddNode"
#
#-----------------------------------------------------------------------
def __TestAddNode(NodeInfo,PeerKey,LogPath):

    print('*** New Node:',NodeInfo['MAC'],'=',NodeInfo['Hostname'])

    if NodeInfo['Segment'] is None:
        NodeInfo['Segment'] = 'vpn99'

    try:
        KeyFile = open(os.path.join(LogPath,'new_peers','ffs-'+NodeInfo['NodeID']), mode='w')
        KeyFile.write('#MAC: %s\n#Hostname: %s\n#Segment: %s\nkey \"%s\";' %
                      (NodeInfo['MAC'],NodeInfo['Hostname'],NodeInfo['Segment'],PeerKey))
        KeyFile.close()
    except:
        return False

    return True



#-----------------------------------------------------------------------
# function "__TestDelNode"
#
#-----------------------------------------------------------------------
def __TestDelNode(NodeInfo,PeerKey,LogPath):

    try:
        KeyFile = open(os.path.join(LogPath,'new_peers','ffs-'+NodeInfo['NodeID']), mode='w')
        KeyFile.write('#MAC: %s\n#Hostname: %s\n#Segment: %s\nkey \"%s\";' %
                      (NodeInfo['MAC'],NodeInfo['Hostname'],NodeInfo['Segment'],PeerKey))
        KeyFile.close()
    except:
        return False

    return True



#-----------------------------------------------------------------------
# function "RegisterNode"
#
#-----------------------------------------------------------------------
def RegisterNode(NodeInfo,PeerKey,GitRepo):

    if NodeInfo['Segment'] is None:
        NodeInfo['Segment'] = 'vpn99'    #......... remove later when we have correct segment

    try:
        KeyFile = open(os.path.join(LogPath,'new_peers','ffs-'+NodeInfo['NodeID']), mode='w')
        KeyFile.write('#MAC: %s\n#Hostname: %s\n#Segment: %s\nkey \"%s\";' %
                      (NodeInfo['MAC'],NodeInfo['Hostname'],NodeInfo['Segment'],PeerKey))
        KeyFile.close()
    except:
        return False

    return True



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
parser.add_argument('--json', dest='JSONPATH', action='store', required=True, help='Path to Database with Keys and MACs')
parser.add_argument('--blacklist', dest='BLACKLIST', action='store', required=True, help='Blacklist Folder')

args = parser.parse_args()
PeerKey  = args.PEERKEY
FastdPID = int(args.FASTDPID)

print('Onboarding of',PeerKey,'started with PID =',psutil.Process().pid,'...')

#if True:
if not os.path.exists(args.BLACKLIST+'/'+args.PEERKEY):
    setBlacklistFile(os.path.join(args.BLACKLIST,PeerKey))

    print('... loading Account Data ...')
    AccountsDict = LoadAccounts(os.path.join(args.JSONPATH,AccountFileName))  # All needed Accounts for Accessing resricted Data

    print('... getting Fastd Status Socket ...')
    FastdStatusSocket = getFastdStatusSocket(FastdPID)

    if os.path.exists(FastdStatusSocket) and AccountsDict is not None:

        print('... getting MeshMAC ...')
        MeshMAC = getMeshMAC(FastdStatusSocket)

        print('... loading KeyDataDict ...')
        KeyDataDict = LoadKeyData(args.JSONPATH)

        if MeshMAC is not None and KeyDataDict is not None:
            print('... MeshMAC and KeyDataDict loaded.')

            BatmanVpnMAC = ActivateBatman(args.BATIF,args.VPNIF)

            if BatmanVpnMAC == MeshMAC:
                print('... Fastd and Batman are consistent:',MeshMAC)
                NodeIPv6 = 'fe80::' + hex(int(MeshMAC[0:2],16) ^ 0x02)[2:] + MeshMAC[3:8]+'ff:fe'+MeshMAC[9:14]+MeshMAC[15:17]+'%'+args.VPNIF
                NodeInfo = getNodeInfos(NodeIPv6)
                PeerMAC  = GetBatmanNodeMAC(args.BATIF,BatmanVpnMAC)

                if NodeInfo is not None:  # Data from status page of Node
                    if PeerMAC is not None and PeerMAC != NodeInfo['MAC']:
                        print('!! PeerMAC mismatch Status Page <> Batman:',NodeInfo['MAC'],PeerMAC)

                    NodeID      = NodeInfo['NodeID']
                    PeerMAC     = NodeInfo['MAC']
                    PeerName    = NodeInfo['Hostname']
                    PeerSegment = NodeInfo['Segment']
                else:  # Fallback
                    if PeerMAC is not None:
                        NodeID      = PeerMAC.replace(':','')
                        PeerName    = PeerFile
                        PeerSegment = None

                if PeerMAC is not None:
#                    if PeerSegment is None:    #..........................................................................................
                    PeerSegment = getBatmanSegment(args.BATIF,args.VPNIF)

                    PeerFile    = 'ffs-'+NodeID
                    DnsSegment  = checkDNS(PeerFile+'-'+PeerKey[:12],AccountsDict['DNS']['Server'])    # -> 'vpn??'
                    print('>>> DNS / Mesh =',DnsSegment,'/',PeerSegment)

                    if DnsSegment is None:  # Node is not registered in DNS

                        if PeerKey[:12] in KeyDataDict['Key2Mac']:
                            print('++ Key is already in use:',NodeID,'/',PeerMAC,'->',
                                  KeyDataDict['Key2Mac'][PeerKey[:12]]['PeerMAC'],'=',KeyDataDict['Key2Mac'][PeerKey[:12]]['SegDir'],'/',KeyDataDict['Key2Mac'][PeerKey[:12]]['KeyFile'])

                        if PeerMAC in KeyDataDict['Mac2Key']:
                            print('++ MAC is already in use:',NodeID,'/',PeerMAC,'->',
                                  KeyDataDict['Mac2Key'][PeerMAC]['SegDir'],'/',KeyDataDict['Mac2Key'][PeerMAC]['KeyFile'],'=',KeyDataDict['Mac2Key'][PeerMAC]['PeerKey']+'...')

#                        RegisterNode(NodeInfo,PeerKey,args.GITREPO)
                        __TestAddNode(NodeInfo,PeerKey,args.JSONPATH)

                    else:  # Node is already registered in DNS
                        if PeerKey[:12] in KeyDataDict['Key2Mac']:

                            if KeyDataDict['Key2Mac'][PeerKey[:12]]['PeerMAC'] != PeerMAC:
                                print('!! MAC Mismatch between Git and Peer:',KeyDataDict['Key2Mac'][PeerKey[:12]]['PeerMAC'],'<>',PeerMAC)
                            else:  # MAC from DNS == MAC from Git
                                if PeerSegment is not None and PeerSegment != DnsSegment:
                                    print('++ Node must be moved to other Segment:',PeerFile,'/',DnsSegment,'->',PeerSegment)
                                else:
                                    print('++ Node is already registered:',PeerFile,'/',DnsSegment)

                        else:  # Node is in DNS but not in Git
                            print('++ DNS is faster than Git:',PeerKey,'=',PeerMAC)

                    #endif (Handling of Registration) ----------

                else: # PeerMAC cannot be determined
                    print('++ Node status information not available!')

            else:
                print('++ Node MAC via Batman <> via FastD:',BatmanMAC,'<>',MeshMAC)

            DeactivateBatman(args.BATIF,args.VPNIF)

        else:
            print('++ MeshMAC (or KeyDataDict) is not available!',MeshMAC)

    else:
        print('!! ERROR: Accounts or Fastd Status Socket not available!')

else:
    print('!! ERROR: Node is blacklisted:',PeerKey)


os.kill(FastdPID,signal.SIGUSR2)    # reset fastd connections

exit(0)
