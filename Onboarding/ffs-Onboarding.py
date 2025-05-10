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
#      --mtu       = fastd-MTU (e.g. 1340)                                                #
#      --batman    = batman-Interface (e.g. batWW)                                        #
#      --peerkey   = fastd-Key from Peer                                                  #
#      --gitrepo   = Git Repository with KeyFiles                                         #
#      --data      = Path to Databases                                                    #
#      --blacklist = Path to Blacklisting Files                                           #
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

import urllib.request
import json
import re
import hashlib
import fcntl
import argparse

from glob import glob

from class_ffLocation import *
from class_ffDnsServer import *


#----- Needed Data-Files -----
AccountFileName = '.Accounts.json'

#----- Global Constants -----
CPE_SAFE_GLUON           = '1.4+2018-06-24'
CPE_TEMP_SEGMENT         = 30
DEFAULT_SEGMENT          = 3

NODETYPE_LEGACY          = 1    # Gluon <  0.7+2016.01.02
NODETYPE_SEGMENT_LIST    = 2    # Gluon >= 0.7+2016.01.02
NODETYPE_DNS_SEGASSIGN   = 3    # Gluon >= 1.0+2017-02-14
NODETYPE_MTU_1340        = 4    # Gluon >= 1.3+2017-09-13
NODETYPE_MCAST_ff05      = 5    # Gluon >= 1.4+2017-12-12

SEGASSIGN_DOMAIN = 'segassign.freifunk-stuttgart.de'

RESPONDD_PORT    = 1001
RESPONDD_TIMEOUT = 5.0

MacAdrTemplate   = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
GwMacTemplate    = re.compile('^02:00:((0a)|(3[1-9]))(:[0-9a-f]{2}){3}')

LocationTemplate = re.compile('[0-9]{1,2}[.][0-9]{1,}')
ZipTemplate      = re.compile('^[0-9]{5}$')
DnsNodeTemplate  = re.compile('^ffs(-[0-9a-f]{12}){2}$')


BadNameTemplate  = re.compile('.*[|/\\<>]+.*')




#-----------------------------------------------------------------------
# Function "LoadAccounts"
#
#   Load Accounts from Accounts.json into AccountsDict
#
#-----------------------------------------------------------------------
def LoadAccounts(AccountFile):

    print('... loading Account Data ...')
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
# function "LoadGitInfo"
#
#-----------------------------------------------------------------------
def LoadGitInfo(GitPath):

    print('... Loading Git Info ...')
    GitDataDict = None
    NodeCount = 0

    try:
        #----- Synchronizing Git Acccess -----
        GitLockName = os.path.join('/tmp','.'+os.path.basename(GitPath)+'.lock')
        LockFile = open(GitLockName, mode='w+')
        fcntl.lockf(LockFile,fcntl.LOCK_EX)

        GitRepo   = git.Repo(GitPath)
        GitOrigin = GitRepo.remotes.origin

        if GitRepo.is_dirty() or len(GitRepo.untracked_files) > 0:
            print('!! The Git Repository is not clean - cannot register Node!')
        else:
            GitDataDict = { 'NodeID':{}, 'Key':{} }
            GitOrigin.pull()
            KeyFileList = glob(os.path.join(GitPath,'vpn*/peers/ffs-*'))

            for KeyFilePath in KeyFileList:
                ffNodeSeg = int(os.path.dirname(KeyFilePath).split("/")[-2][3:])

                if ffNodeSeg > 0 and ffNodeSeg < 99:
                    ffNodeID  = os.path.basename(KeyFilePath)[4:]

                    with open(KeyFilePath,'r') as KeyFile:
                        KeyData  = KeyFile.read()
                        NodeName = None
                        fixedSeg = None

                        for DataLine in KeyData.split('\n'):
                            if DataLine.lower().startswith('key '):
                                NodeCount += 1
                                ffNodeKey = DataLine.split(' ')[1][1:-2]

                                GitDataDict['NodeID'][ffNodeID] = {
                                    'Hostname' : None,
                                    'Key'      : ffNodeKey,
                                    'Segment'  : ffNodeSeg,
                                    'fixed'    : None
                                }

                                GitDataDict['Key'][ffNodeKey] = ffNodeID
                            elif DataLine.lower().startswith('#segment: '):
                                fixedSeg = DataLine[10:].lower()
                            elif DataLine.lower().startswith('#hostname: '):
                                NodeName = DataLine[11:]

                        if ffNodeID in GitDataDict['NodeID']:
                            GitDataDict['NodeID'][ffNodeID]['Hostname'] = NodeName
                            GitDataDict['NodeID'][ffNodeID]['fixed']    = fixedSeg

    except:
        print('!!! ERROR accessing Git Reository!')
        GitDataDict = None

    finally:
        del GitOrigin
        del GitRepo

        fcntl.lockf(LockFile,fcntl.LOCK_UN)
        LockFile.close()

        print('... Git-Infos loaded:',NodeCount)

    return GitDataDict



#-----------------------------------------------------------------------
# function "getFastdStatusSocket"
#
#-----------------------------------------------------------------------
def getFastdStatusSocket(pid):

    print('... getting Fastd Status Socket ...')
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
# function "getNodeFastdMAC"
#
#-----------------------------------------------------------------------
def getNodeFastdMAC(FastdStatusSocket):

    print('... getting fastd-MAC from fastd status ...')
    FastdMAC = None
    Retries  = 10

    while FastdMAC is None and Retries > 0:
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
                            for FastdMAC in FastdStatusJson['peers'][PeerKey]['connection']['mac_addresses']:
                                break
        except:
            FastdMAC = None
            print('++ Error on getting fastd-MAC !!')

    return FastdMAC



#-----------------------------------------------------------------------
# function "ActivateBatman"
#
#    -> MAC of fastd Interface attached to bat0 on Node via "batctl -n"
#-----------------------------------------------------------------------
def ActivateBatman(BatmanIF, FastdIF):

    print('... Activating Batman ...')
    Retries = 30
    NeighborMAC = None

    try:
        subprocess.run(['/usr/sbin/batctl','meshif',BatmanIF,'if','add',FastdIF])
        subprocess.run(['/sbin/ip','link','set','dev',BatmanIF,'up'])
        BatctlResult = subprocess.run(['/usr/sbin/batctl','meshif',BatmanIF,'if'], stdout=subprocess.PIPE)
    except:
        print('++ Cannot bring up',BatmanIF,'!')
    else:
        print('... Batman Interface',BatmanIF,'is up ...',BatctlResult.stdout.decode('utf-8'))

        while Retries > 0:
            Retries -= 1
            time.sleep(2)
            NeighborMAC = None

            try:
                BatctlN = subprocess.run(['/usr/sbin/batctl','meshif',BatmanIF,'n'], stdout=subprocess.PIPE)
                BatctlResult = BatctlN.stdout.decode('utf-8')
            except:
                print('++ ERROR on running batctl n:',BatmanIF,'->',FastdIF)
            else:
                for NeighborInfo in BatctlResult.split('\n'):
                    if len(NeighborInfo.strip()) > 0:
                        NeighborDetails = NeighborInfo.split()

                        if NeighborDetails[0] == FastdIF:
                            Retries = 0

                            if NeighborMAC is None:
                                NeighborMAC = NeighborDetails[1]
                            else:
                                print('++ Multiple Neighbors on',BatmanIF,'!')
                                NeighborMAC = None
                                break

    return NeighborMAC



#-----------------------------------------------------------------------
# function "DeactivateBatman"
#
#-----------------------------------------------------------------------
def DeactivateBatman(BatmanIF, FastdIF):

    print('... Deactivating Batman ...')

    try:
        subprocess.run(['/sbin/ip','link','set','dev',BatmanIF,'down'])
        subprocess.run(['/usr/sbin/batctl','meshif',BatmanIF,'if','del',FastdIF])
        print('... Batman Interface',BatmanIF,'is down.')
    except:
        print('++ Cannot shut down',BatmanIF,'!')
        pass

    return



#-----------------------------------------------------------------------
# function "GenerateGluonMACs(MainMAC)"
#
#   Get all related MACs based on Primary MAC for Gluon >= 2016.2
#
# reference = Gluon Source:
#
#   /package/gluon-core/luasrc/usr/lib/lua/gluon/util.lua
#
# function generate_mac(i)
# -- 0 + 8: client0; mesh-on-WAN
# -- 1 + 9: mesh0
# -- 2 + a: ibss0
# -- 3 + b: wan_radio0 (private WLAN); batman-adv primary address
# -- 4 + c: client1; mesh-on-LAN
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
def GenerateGluonMACs(MainMAC):

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
# function "getNodeMACviaBatman"
#
#    -> NodeMAC
#-----------------------------------------------------------------------
def getNodeMACviaBatman(BatmanIF, FastdMAC):

    print('Find Node MAC via Batman TG ...')
    NodeMAC = None

    try:
        BatctlTG = subprocess.run(['/usr/sbin/batctl','meshif',BatmanIF,'tg'], stdout=subprocess.PIPE)
        BatmanTransTable = BatctlTG.stdout.decode('utf-8')
    except:
        print('!! ERROR on Batman Translation Table of',BatmanIF)
        BatmanTransTable = []

    for TransItem in BatmanTransTable:
        BatctlInfo = TransItem.replace('(',' ').replace(')',' ').split()

        if len(BatctlInfo) == 9 and MacAdrTemplate.match(BatctlInfo[1]) and not GwMacTemplate.match(BatctlInfo[1]) and BatctlInfo[2] == '-1':
            BatNodeMAC = BatctlInfo[1]
            BatMeshMAC = BatctlInfo[5]

            if BatMeshMAC[:16] == FastdMAC[:16]:
                BatmanMacList = GenerateGluonMACs(BatNodeMAC)

                if BatMeshMAC in BatmanMacList and FastdMAC in BatmanMacList:  # Data is from current Node
                    if NodeMAC is None:
                        print('++ Node found in Batman Translation Table: %s' % (BatNodeMAC))
                        NodeMAC = BatNodeMAC
                    else:
                        print('!! Unknown MACs in Batman Translation Table: %s -> %s + %s' % (BatMeshMAC,NodeMAC,BatNodeMAC))
                        NodeMAC = None
                        break

    return NodeMAC



#-----------------------------------------------------------------------
# function "InfoFromRespondd"
#
#  -> NodeJsonDict
#-----------------------------------------------------------------------
def InfoFromRespondd(NodeMAC, NodeIF):

    NodeIPv6 = 'fe80::' + hex(int(NodeMAC[0:2],16) ^ 0x02)[2:]+NodeMAC[3:8]+'ff:fe'+NodeMAC[9:14]+NodeMAC[15:17] + '%'+NodeIF

    print('Requesting Nodeinfo via respondd from %s ...' % (NodeIPv6))
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

            ResponddSock.sendto('nodeinfo'.encode("UTF-8"), DestAddrObj)
            NodeJsonDict = json.loads(ResponddSock.recv(4096).decode('UTF-8'))
            ResponddSock.close()
        except:
#            print('++ Error on respondd!')
            NodeJsonDict = None
            time.sleep(2)

    return NodeJsonDict



#-----------------------------------------------------------------------
# function "GetNodeType"
#
#  -> NodeType
#-----------------------------------------------------------------------
def GetNodeType(GluonVersion, FastdMTU):

    NodeType = None

    if GluonVersion is not None:
        if GluonVersion[:14] >= '1.4+2017-12-12':
            NodeType = NODETYPE_MCAST_ff05
        elif GluonVersion[:14] >= '1.3+2017-09-13':
            NodeType = NODETYPE_MTU_1340
        elif GluonVersion[:14] >= '1.0+2017-02-14':
            if FastdMTU == 1340:
                NodeType = NODETYPE_MTU_1340
            else:
                NodeType = NODETYPE_DNS_SEGASSIGN
        elif GluonVersion[:14] >= '0.7+2016.01.02':
            NodeType = NODETYPE_SEGMENT_LIST
        else:
            NodeType = NODETYPE_LEGACY

    return NodeType



#-----------------------------------------------------------------------
# function "AnalyseNodeJson"
#
#  -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def AnalyseNodeJson(NodeJson, NodeVpnMAC, FastdMTU):

    NodeInfoDict = {
        'NodeType' : None,
        'GluonVer' : None,
        'Updater'  : None,
        'NodeID'   : None,
        'MAC'      : None,
        'Hostname' : None,
        'Hardware' : None,
        'Segment'  : None,
        'Location' : None,
        'Contact'  : None
    }

    if 'node_id' in NodeJson and 'network' in NodeJson and 'hostname' in NodeJson:
        if 'mac' in NodeJson['network'] and 'addresses' in NodeJson['network'] and 'mesh' in NodeJson['network']:
            if NodeJson['node_id'].strip() == NodeJson['network']['mac'].strip().replace(':',''):

                NodeInfoDict['NodeID']   = NodeJson['node_id'].strip()
                NodeInfoDict['MAC']      = NodeJson['network']['mac'].strip()
                NodeInfoDict['Hostname'] = NodeJson['hostname'].strip()

                if 'software' in NodeJson:
                    if 'firmware' in NodeJson['software']:
                        if 'release' in NodeJson['software']['firmware']:
                            NodeInfoDict['GluonVer'] = NodeJson['software']['firmware']['release']
                            NodeInfoDict['NodeType'] = GetNodeType(NodeInfoDict['GluonVer'], FastdMTU)

                        BatmanMacList = GenerateGluonMACs(NodeInfoDict['MAC'])

                        if NodeVpnMAC not in BatmanMacList:
                            print(BatmanMacList)
                            print('!!! Invalid Batman MAC schema: VpnMAC = %s' % (NodeVpnMAC))
                            NodeInfoDict['NodeType'] = None

                    if 'autoupdater' in NodeJson['software']:
                        if 'enabled' in NodeJson['software']['autoupdater']:
                            NodeInfoDict['Updater'] = NodeJson['software']['autoupdater']['enabled']

                if 'owner' in NodeJson:
                    if 'contact' in NodeJson['owner']:
                        NodeInfoDict['Contact'] = NodeJson['owner']['contact']

                if 'hardware' in NodeJson:
                    if 'model' in NodeJson['hardware']:
                        NodeInfoDict['Hardware'] = NodeJson['hardware']['model'].strip()
                    else:
                        NodeInfoDict['Hardware'] = '???'

                print('>>> NodeID   =',NodeInfoDict['NodeID'])
                print('>>> MAC      =',NodeInfoDict['MAC'])
                print('>>> Hostname =',NodeInfoDict['Hostname'].encode('utf-8'))
                print('>>> Hardware =',NodeInfoDict['Hardware'])
                print('>>> GluonVer =',NodeInfoDict['GluonVer'])
                print('>>> Updater  =',NodeInfoDict['Updater'])
                print('>>> Contact  =',NodeInfoDict['Contact'])

                if 'location' in NodeJson:
                    if ('longitude' in NodeJson['location'] and 'latitude' in NodeJson['location']) or 'zip' in NodeJson['location']:
                        NodeInfoDict['Location'] = NodeJson['location']

                Segment = None

                for NodeIPv6 in NodeJson['network']['addresses']:
                    print('>>> IPv6 =',NodeIPv6)
                    if NodeIPv6[0:12] == 'fd21:b4dc:4b':
                        if NodeIPv6[12:14] == '1e':
                            Segment = 0
                        else:
                            Segment = int(NodeIPv6[12:14])

                        if NodeInfoDict['Segment'] is None:
                            NodeInfoDict['Segment'] = Segment
                        elif NodeInfoDict['Segment'] != Segment:
                            print('!! Addresses of multiple Segments:',NodeInfoDict['Segment'],'<>',Segment)
                            NodeInfoDict['Segment'] = None
                            break

                print('>>> NodeInfo Segment =',NodeInfoDict['Segment'])
            else:
                print('+++ inconsistent Node Info: MAC and Node-ID do not match!')

    if NodeInfoDict['NodeType'] is None or NodeInfoDict['NodeID'] is None or NodeInfoDict['MAC'] is None or NodeInfoDict['Hostname'] is None:
        print('+++ corrupted Node Info!')
        NodeInfoDict = None
    else:
        print('... Node Info is consistent.\n')

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "getNodeInfos"
#
#    -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def getNodeInfos(FastdMAC, FastdIF, FastdMTU, BatmanIF):

    NodeJson = InfoFromRespondd(FastdMAC,FastdIF)

    if NodeJson is None:
        print('++ No info via Respondd from VPN-Interface - Fallback to Batman TG ...')
        NodeMAC = getNodeMACviaBatman(BatmanIF,FastdMAC)

        if NodeMAC is not None:
            NodeJson = InfoFromRespondd(NodeMAC,BatmanIF)

    if NodeJson is None:
        print('++ No info via Respondd!')
        NodeInfoDict = None
    else:
        NodeInfoDict = AnalyseNodeJson(NodeJson,FastdMAC,FastdMTU)

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "getBatmanSegment"
#
#   returns Segment or None (node is not meshing)
#-----------------------------------------------------------------------
def getBatmanSegment(BatmanIF):

    print('Find Segment via Batman Gateways ...')
    Retries = 30
    BatSeg = None
    CheckTime = 0

    while Retries > 0:
        Retries -= 1
        time.sleep(2)
        CheckTime += 2

        try:
            BatctlGwl = subprocess.run(['/usr/sbin/batctl','meshif',BatmanIF,'gwl'], stdout=subprocess.PIPE)
            gwl = BatctlGwl.stdout.decode('utf-8')

            for Gateway in gwl.split('\n'):
                if Gateway[3:10] == '02:00:3':
                    GwSeg = int(Gateway[12:14])
                elif Gateway[3:12] == '02:00:0a:':
                    GwSeg = int(Gateway[15:17])
                else:
                    GwSeg = None

                if GwSeg is not None:
                    if BatSeg is None:
                        BatSeg = GwSeg
                        Retries = 2
                    elif GwSeg != BatSeg:
                        BatSeg = None        # Shortcut: Correct Segment cannot be determined
                        Retries = 0
                        break;
        except:
            print('++ ERROR accessing',BatmanIF)
            BatSeg = None

    print('... Batman Segment =',BatSeg,'(waiting',CheckTime,'seconds)')
    return BatSeg


#-----------------------------------------------------------------------
# function "GetGeoSegment"
#
#   Get Segment from Regions
#-----------------------------------------------------------------------
def GetGeoSegment(NodeLocation, GitPath, DatabasePath):

    print('Get Segment from Geo Position ...', NodeLocation)

    GpsSegment  = None
    ZipSegment  = None

    if NodeLocation is None:
        print('... No Geo Position available.')
        return None

    ffLocationInfo = ffLocation(GitPath, DatabasePath)

    if not ffLocationInfo.LocationDataOK():
        print('!! No Region Data available !!!')
        return None

    if 'longitude' in NodeLocation and 'latitude' in NodeLocation:
        lon = NodeLocation['longitude']
        lat = NodeLocation['latitude']
        print('... Checking GPS Data (lat | lon):', str(lat), '|', str(lon))

        if LocationTemplate.match(str(lat)) and LocationTemplate.match(str(lon)):
            (GpsZipCode, GpsRegion, GpsSegment) = ffLocationInfo.GetLocationDataFromGPS(lon, lat)

        if GpsSegment is None:
            print('** Bad GPS Data - no GpsSegment available !!')
        else:
            print('>>> GpsSegment =', GpsSegment)

    if 'zip' in NodeLocation:
        ZipCode = str(NodeLocation['zip'])[:5]
        print('... Checking ZIP-Code', ZipCode)

        if ZipTemplate.match(ZipCode):
            (ZipRegion, ZipSegment) = ffLocationInfo.GetLocationDataFromZIP(ZipCode)

            print('>>> ZipSegment =', ZipSegment)

            if GpsSegment is not None:
                if ZipSegment is not None and ZipSegment != GpsSegment:
                    print('!! Segment Mismatch GPS <> ZIP:', GpsSegment, '<>', ZipSegment)
            elif ZipSegment is not None:
                GpsSegment = ZipSegment
                print('++ Segment set by ZIP-Code:', ZipSegment)
        else:
            print('*** Invalid ZIP-Code Format:', ZipCode)

    return GpsSegment



#-----------------------------------------------------------------------
# function "WriteNodeKeyFile"
#
#-----------------------------------------------------------------------
def WriteNodeKeyFile(KeyFileName, NodeInfo, GitFixSeg, PeerKey):

    print('... Writing KeyFile:',KeyFileName)

    KeyFile = open(KeyFileName, mode='w')

    if GitFixSeg is not None:
        KeyFile.write('#MAC: %s\n#Hostname: %s\n#Segment: %s\nkey \"%s\";\n' % (NodeInfo['MAC'],NodeInfo['Hostname'],GitFixSeg,PeerKey))
    else:
        KeyFile.write('#MAC: %s\n#Hostname: %s\nkey \"%s\";\n' % (NodeInfo['MAC'],NodeInfo['Hostname'],PeerKey))

    KeyFile.close()
    print('... done.')
    return



#-----------------------------------------------------------------------
# function "RegisterNode"
#
#    NodeInfo = {
#        'NodeType' : NODETYPE_LEGACY, NODETYPE_SEGMENT_LIST, NODETYPE_DNS_SEGASSIGN, NODETYPE_MTU_1340
#        'GluonVer' : None,
#        'NodeID'   : None,
#        'MAC'      : None,
#        'Hostname' : None,
#        'Segment'  : None,
#        'Location' : None,
#        'Contact'  : None
#    }
#
#
#    GitInfo = {
#        'NodeID' : { <NodeID> -> {'Key','Segment','fixed'} },
#        'Key'    : { <Key>    -> ffNodeID }
#    }
#
#
#   Actions:
#     NEW_KEY
#     NEW_NODE
#     NEW_SEGMENT
#
#-----------------------------------------------------------------------
def RegisterNode(PeerKey, NodeInfo, GitInfo, GitPath, DatabasePath, AccountsDict):

    NeedCommit = False
    Action     = None
    ErrorCode  = 0


    #========== Analyse Situation ==========
    NodeID     = NodeInfo['NodeID']
    NewSegment = NodeInfo['Segment']

    if PeerKey in GitInfo['Key']:
        if GitInfo['Key'][PeerKey] != NodeID:
            print('++ Key already in use by other Node: vpn%02d / ffs-%s\n' % (GitInfo['NodeID'][GitInfo['Key'][PeerKey]]['Segment'], GitInfo['Key'][PeerKey]))
            return 0

    if NodeID in GitInfo['NodeID']:    # Node is known in Git ...
        GitKey      = GitInfo['NodeID'][NodeID]['Key']
        GitSegment  = GitInfo['NodeID'][NodeID]['Segment']
        GitFixSeg   = GitInfo['NodeID'][NodeID]['fixed']
        GitNodeName = GitInfo['NodeID'][NodeID]['Hostname']

        print('>>> NodeID already in Git: vpn%02d / %s\n' % (GitSegment, NodeID))

        if GitFixSeg is not None:
            if PeerKey != GitKey and NodeInfo['Hostname'].lower() != GitNodeName.lower():
                GitFixSeg = None
            elif GitFixSeg.lower()[:3] == 'fix':
                NewSegment = GitSegment
                print('... fix Segment = %02d ...' % (GitSegment))
            elif NewSegment is None and GitFixSeg.lower()[:3] == 'man':
                NewSegment = GitSegment
                print('... manually set Segment = %02d ...' % (GitSegment))
            elif NewSegment is None and GitFixSeg.lower()[:3] == 'mob':
                NodeInfo['Location'] = None
                print('... mobile Node without specific Segment ...')

        if NewSegment is None:    # no specific segment required
            NewSegment = GetGeoSegment(NodeInfo['Location'], GitPath, DatabasePath)

            if NewSegment is None:    # no segment specified
                NewSegment = GitSegment
                print('... keeping current Segment = %02d ...' % (GitSegment))

            if NodeInfo['NodeType'] < NODETYPE_DNS_SEGASSIGN and NewSegment > 8:
                print('... replacing regular Segment %02d with default = %02d ...' % (NewSegment, DEFAULT_SEGMENT))
                NewSegment = DEFAULT_SEGMENT

        if PeerKey == GitKey and NewSegment == GitSegment:
            print('... Node is already registered: vpn%02d / ffs-%s-%s\n' % (GitSegment, NodeID, GitKey[:12]))
            return 0

        if PeerKey != GitKey:
            Action = 'NEW_KEY'

        if NewSegment != GitSegment:
            if Action is None:
                Action = 'NEW_SEGMENT'
            else:
                Action = 'NEW_KEY + NEW_SEGMENT'

    else:  # NodeID is not in Git ...
        print('*** NodeID not in Git: %s\n' % (NodeID))
        Action = 'NEW_NODE'

        GitKey      = None
        GitSegment  = None
        GitFixSeg   = None
        GitNodeName = None

        if NewSegment is None:    # no specific segment required
            NewSegment = GetGeoSegment(NodeInfo['Location'], GitPath, DatabasePath)

            if NewSegment is None:    # no segment specified
                NewSegment = DEFAULT_SEGMENT
                print('... setting default Segment = %02d ...' % (DEFAULT_SEGMENT))
            elif NodeInfo['NodeType'] < NODETYPE_DNS_SEGASSIGN and NewSegment > 8:
                print('... replacing regular Segment %02d with default = %02d ...' % (NewSegment, DEFAULT_SEGMENT))
                NewSegment = DEFAULT_SEGMENT
        else:
            print('>>> Node is meshing in segment %02d.' % (NewSegment))


    #========== Actions depending of Situation ==========
    NewPeerFile    = 'vpn%02d/peers/ffs-%s' % (NewSegment, NodeInfo['NodeID'])
    NewPeerDnsName = 'ffs-%s-%s' % (NodeID, PeerKey[:12])
    NewPeerDnsIPv6 = '%s%d' % (SegAssignIPv6Prefix, NewSegment)
    NewPeerDnsIPv4 = '%s%d' % (SegAssignIPv4Prefix, NewSegment)

    print('\n>>> Action = %s' % (Action))
    print('>>> New Peer Data: %s = %s -> %s' % (NewPeerDnsName, NewPeerFile, NewPeerDnsIPv6))

    try:
        #----- Synchronizing Git Acccess -----
        GitLockName = os.path.join('/tmp','.'+os.path.basename(GitPath)+'.lock')
#        print('>>> GitLockName:',GitLockName)
        LockFile = open(GitLockName, mode='w+')
        fcntl.lockf(LockFile,fcntl.LOCK_EX)
#        print('>>> lock is set.')

        #----- Handling registration -----
        GitRepo   = git.Repo(GitPath)
        GitIndex  = GitRepo.index
        GitOrigin = GitRepo.remotes.origin

        SegAssignDnsServer = ffDnsServer(SEGASSIGN_DOMAIN, AccountsDict['DNS'])

        if GitRepo.is_dirty() or len(GitRepo.untracked_files) > 0 or SegAssignDnsServer.ReadOnly:
            print('!! The Git Repository and/or DNS are not clean - cannot register Node!')

        else:  # Git and DNS ready for registering node ...

            if GitKey is None:    # new Node
                if not os.path.exists(os.path.join(GitPath, NewPeerFile)):
                    WriteNodeKeyFile(os.path.join(GitPath, NewPeerFile), NodeInfo, None, PeerKey)
                    GitIndex.add([NewPeerFile])

                    SegAssignDnsServer.ReplaceEntry(NewPeerDnsName, NewPeerDnsIPv6)
                    SegAssignDnsServer.ReplaceEntry(NewPeerDnsName, NewPeerDnsIPv4)

                    print('*** New Node: vpn%02d / ffs-%s = \"%s\" (%s...)' % (NewSegment, NodeInfo['NodeID'], NodeInfo['Hostname'], PeerKey[:12]))
                    NeedCommit = True

                else:
                    print('... Key File was already added by other process.')

            else:    # existing Node
                OldPeerFile    = 'vpn%02d/peers/ffs-%s' % (GitSegment, NodeID)
                OldPeerDnsName = 'ffs-%s-%s' % (NodeID, GitKey[:12])
                print('>>> Existing Peer Data: %s = %s' %(OldPeerDnsName, OldPeerFile))

                if os.path.exists(os.path.join(GitPath, OldPeerFile)):
                    if NewSegment != GitSegment:
                        GitIndex.remove([OldPeerFile])
                        os.rename(os.path.join(GitPath, OldPeerFile), os.path.join(GitPath, NewPeerFile))
                        print('*** New Segment for existing Node: vpn%02d -> vpn%02d / %s = \"%s\"' % (GitSegment, NewSegment, NodeInfo['MAC'], NodeInfo['Hostname']))

                    if PeerKey != GitKey:
                        print('*** New Key for existing Node: vpn%02d / %s = \"%s\" -> %s...' % (NewSegment, NodeInfo['MAC'], NodeInfo['Hostname'], PeerKey[:12]))

                    WriteNodeKeyFile(os.path.join(GitPath,NewPeerFile), NodeInfo, GitFixSeg, PeerKey)
                    GitIndex.add([NewPeerFile])
                    NeedCommit = True

                    if NewPeerDnsName != OldPeerDnsName:
                        SegAssignDnsServer.DelEntry(OldPeerDnsName, None)
                        SegAssignDnsServer.AddEntry(NewPeerDnsName, NewPeerDnsIPv6)
                        SegAssignDnsServer.AddEntry(NewPeerDnsName, NewPeerDnsIPv4)
                    else:
                        SegAssignDnsServer.ReplaceEntry(NewPeerDnsName, NewPeerDnsIPv6)
                        SegAssignDnsServer.ReplaceEntry(NewPeerDnsName, NewPeerDnsIPv4)
                else:
                    print('... Key File was already changed by other process.')

            if NeedCommit:
                GitIndex.commit('Onboarding (%s) of %s = \"%s\" in Segment %02d' % (Action, NodeInfo['MAC'], NodeInfo['Hostname'], NewSegment))
                GitOrigin.config_writer.set('url', AccountsDict['Git']['URL'])
                print('... doing Git pull ...')
                GitOrigin.pull()
                print('... doing Git push ...')
                GitOrigin.push()

                if not SegAssignDnsServer.CommitChanges():
                    print('+++ DNS update failed !!')

                MailBody = 'Automatic Onboarding (%s) in Segment %02d:\n\n#MAC: %s\n#Hostname: %s\nkey \"%s\";\n' % (Action, NewSegment, NodeInfo['MAC'], NodeInfo['Hostname'], PeerKey)
                print(MailBody)

                SendEmail('Onboarding of Node \"%s\" by %s' % (NodeInfo['Hostname'], socket.gethostname()), MailBody, AccountsDict['KeyMail'])

    except:
        print('!!! ERROR on registering Node:', Action)
        ErrorCode = 1

    finally:
        del GitOrigin
        del GitIndex
        del GitRepo

        fcntl.lockf(LockFile,fcntl.LOCK_UN)
        LockFile.close()

    return ErrorCode



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


#-----------------------------------------------------------------------
# Function "SendEmail"
#
#   Sending an Email
#
#-----------------------------------------------------------------------
def SendEmail(Subject, MailBody, Account):

    if MailBody != '':
        TimeInfo = datetime.datetime.now()
        TimeString = TimeInfo.strftime('%d.%m.%Y - %H:%M:%S')

        try:
            Email = MIMEText(TimeString+'\n\n'+MailBody)

            Email['Subject'] = Subject
            Email['From']    = Account['Username']
            Email['To']      = Account['MailTo']
            Email['Bcc']     = Account['MailBCC']

            server = smtplib.SMTP(host=Account['Server'], port=Account['Port'], timeout=5)

            if (Account['Password'] != ''):
                server.starttls()
                server.login(Account['Username'], Account['Password'])

            server.send_message(Email)
            server.quit()
            print('\nEmail was sent to', Account['MailTo'])

        except:
            print('!! ERROR on sending Email to', Account['MailTo'])

    return



#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
parser = argparse.ArgumentParser(description='Add or Modify Freifunk Node Registration')
parser.add_argument('--pid',       dest='FASTDPID',  action='store', required=True, help='Fastd PID')
parser.add_argument('--mtu',       dest='FASTDMTU',  action='store', required=True, help='Fastd MTU')
parser.add_argument('--fastd',     dest='VPNIF',     action='store', required=True, help='Fastd Interface')
parser.add_argument('--batman',    dest='BATIF',     action='store', required=True, help='Batman Interface')
parser.add_argument('--peerkey',   dest='PEERKEY',   action='store', required=True, help='Fastd PeerKey')
parser.add_argument('--gitrepo',   dest='GITREPO',   action='store', required=True, help='Git Repository with KeyFiles')
parser.add_argument('--data',      dest='DATAPATH',  action='store', required=True, help='Path to Databases')
parser.add_argument('--blacklist', dest='BLACKLIST', action='store', required=True, help='Blacklist Folder')

args = parser.parse_args()
PeerKey  = args.PEERKEY
FastdPID = int(args.FASTDPID)
FastdMTU = int(args.FASTDMTU)
RetCode  = 0

print('Onboarding of', PeerKey, 'started with PID =', psutil.Process().pid, '/ MTU =', FastdMTU, '...')
BlacklistFile = os.path.join(args.BLACKLIST, PeerKey)

if os.path.exists(BlacklistFile):
    print('!! ERROR: Node is blacklisted:', PeerKey)
else:
    setBlacklistFile(BlacklistFile)

    AccountsDict = LoadAccounts(os.path.join(args.DATAPATH, AccountFileName))
    GitDataDict = LoadGitInfo(args.GITREPO)
    FastdStatusSocket = getFastdStatusSocket(FastdPID)

    if not os.path.exists(FastdStatusSocket) or AccountsDict is None or GitDataDict is None:
        print('!! ERROR: Accounts or Git-Data or Fastd Status Socket not available!')
    else:
        FastdMAC = getNodeFastdMAC(FastdStatusSocket)

        if FastdMAC is None:
            print('++ fastd-MAC is not available!')
        else:
            print('... fastd-MAC =', FastdMAC)

            BatmanVpnMAC = ActivateBatman(args.BATIF, args.VPNIF)    # using "batctl n" (Neighbor) to get VPN-MAC

            if BatmanVpnMAC is None:
                print('++ No valid Batman connection to Node!')
            elif BatmanVpnMAC != FastdMAC:
                print('++ Invalid Node due to mismatch of mesh-vpn MAC (Batman <> Fastd):', BatmanVpnMAC, '<>', FastdMAC)
            else:
                print('... Batman and fastd match on mesh-vpn MAC:', BatmanVpnMAC)
                NodeInfoDict = getNodeInfos(FastdMAC, args.VPNIF, FastdMTU, args.BATIF)    # Info of Node via Respondd

                if NodeInfoDict is None:
                    print('++ Node information not available or inconsistent!')
                elif BadNameTemplate.match(NodeInfoDict['Hostname']):
                    print('!!! Invalid Hostname: %s' % (NodeInfoDict['Hostname']))
                elif NodeInfoDict['NodeType'] == NODETYPE_LEGACY or NodeInfoDict['Segment'] == 0:
                    print('!!! Legacy Node is not supported: %s\n' % (NodeInfoDict['Hostname']))
                elif NodeInfoDict['NodeType'] < NODETYPE_MTU_1340 and not NodeInfoDict['Updater']:
                    print('!!! Node with old Firmware will not be registered if Autoupdater is disabled!')
                else:
                    if (NodeInfoDict['Hardware'].lower().startswith('tp-link cpe') and
                        (NodeInfoDict['NodeType'] < NODETYPE_MTU_1340 or NodeInfoDict['GluonVer'][:14] < CPE_SAFE_GLUON)):
                        print('!! TP-Link CPE with outdated Firmware found: %s!!' % (NodeInfoDict['Hostname']))
                        NodeInfoDict['Segment'] = CPE_TEMP_SEGMENT
                    elif NodeInfoDict['Segment'] is None:
                        NodeInfoDict['Segment'] = getBatmanSegment(args.BATIF)    # meshing segment from "batctl gwl" (batman gateway list)

                    RetCode = RegisterNode(PeerKey, NodeInfoDict, GitDataDict, args.GITREPO, args.DATAPATH, AccountsDict)

            DeactivateBatman(args.BATIF, args.VPNIF)

os.kill(FastdPID, signal.SIGUSR2)    # reset fastd connections

exit(RetCode)
