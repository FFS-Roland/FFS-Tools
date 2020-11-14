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

from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
from glob import glob


#----- Needed Data-Files -----
AccountFileName = '.Accounts.json'
ZipGridName     = 'ZipGrid.json'       # Grid of ZIP Codes from Baden-Wuerttemberg

#----- Global Constants -----
CPE_TEMP_SEGMENT         = 23
DEFAULT_SEGMENT          = 3

NODETYPE_UNKNOWN         = 0
NODETYPE_LEGACY          = 1
NODETYPE_SEGMENT_LIST    = 2
NODETYPE_DNS_SEGASSIGN   = 3
NODETYPE_MTU_1340        = 4

SEGASSIGN_DOMAIN = 'segassign.freifunk-stuttgart.de'
SEGASSIGN_PREFIX = '2001:2:0:711::'

RESPONDD_PORT    = 1001
RESPONDD_TIMEOUT = 5.0

MacAdrTemplate   = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
GwMacTemplate    = re.compile('^02:00:((0a)|(3[1-9]))(:[0-9a-f]{2}){3}')

LocationTemplate = re.compile('[0-9]{1,2}[.][0-9]{1,}')
ZipTemplate      = re.compile('^[0-9]{5}$')
DnsNodeTemplate  = re.compile('^ffs(-[0-9a-f]{12}){2}$')
IPv6NodeTemplate = re.compile('^'+SEGASSIGN_PREFIX+'(([0-9a-f]{1,4}:){1,2})?[0-9]{1,2}$')

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

                if (ffNodeSeg > 0) and (ffNodeSeg < 99):
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
def ActivateBatman(BatmanIF,FastdIF):

    print('... Activating Batman ...')
    Retries = 30
    NeighborMAC = None

    try:
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','add',FastdIF])
        subprocess.run(['/sbin/ip','link','set','dev',BatmanIF,'up'])
        BatctlResult = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if'], stdout=subprocess.PIPE)
    except:
        print('++ Cannot bring up',BatmanIF,'!')
    else:
        print('... Batman Interface',BatmanIF,'is up ...',BatctlResult.stdout.decode('utf-8'))

        while(Retries > 0):
            Retries -= 1
            time.sleep(2)
            NeighborMAC = None

            try:
                BatctlN = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'n'], stdout=subprocess.PIPE)
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
# function "__GenerateGluonMACs(MainMAC)"
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
def __GenerateGluonMACs(MainMAC):

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
# function "__GenerateOldGluonMACs(MainMAC)"
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
def __GenerateOldGluonMACs(MainMAC):

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
# function "__getNodeMACviaBatman"
#
#    -> NodeMAC
#-----------------------------------------------------------------------
def __getNodeMACviaBatman(BatmanIF):

    print('Find Node MAC via Batman TG ...')
    NodeMAC = None

    try:
        BatctlTG = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'tg'], stdout=subprocess.PIPE)
        BatmanTransTable = BatctlTG.stdout.decode('utf-8')
    except:
        print('!! ERROR on Batman Translation Table of',BatmanIF)
        BatmanTransTable = []

    for TransItem in BatmanTransTable:
        BatctlInfo = TransItem.replace('(',' ').replace(')',' ').split()

        if len(BatctlInfo) == 9 and MacAdrTemplate.match(BatctlInfo[1]) and not GwMacTemplate.match(BatctlInfo[1]) and BatctlInfo[2] == '-1':
            BatNodeMAC = BatctlInfo[1]
            BatMeshMAC = BatctlInfo[5]

            if BatMeshMAC[:1] == BatNodeMAC[:1] and BatMeshMAC[9:] == BatNodeMAC[9:]:  # old Gluon MAC schema
                BatmanMacList = __GenerateOldGluonMACs(BatNodeMAC)
            else:  # new Gluon MAC schema
                BatmanMacList = __GenerateGluonMACs(BatNodeMAC)

            if BatMeshMAC in BatmanMacList:  # Data is from Node
                if NodeMAC is None:
                    print('++ Found Node in Batman Translation Table:',BatNodeMAC)
                    NodeMAC = BatNodeMAC
                else:
                    print('!! Multiple Nodes in Batman Translation Table !!')
                    NodeMAC = None
                    break

    return NodeMAC



#-----------------------------------------------------------------------
# function "__InfoFromRespondd"
#
#  -> NodeJsonDict
#-----------------------------------------------------------------------
def __InfoFromRespondd(NodeMAC,NodeIF):

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
# function "__AnalyseNodeJson"
#
#  -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def __AnalyseNodeJson(NodeJson,NodeVpnMAC,FastdMTU):

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

                            if NodeInfoDict['GluonVer'][:14] >= '1.3+2017-09-13':
                                NodeInfoDict['NodeType'] = NODETYPE_MTU_1340
                            elif NodeInfoDict['GluonVer'][:14] >= '1.0+2017-02-14':
                                if FastdMTU == 1340:
                                    NodeInfoDict['NodeType'] = NODETYPE_MTU_1340
                                else:
                                    NodeInfoDict['NodeType'] = NODETYPE_DNS_SEGASSIGN
                            elif NodeInfoDict['GluonVer'][:14] >= '0.7+2016.01.02':
                                NodeInfoDict['NodeType'] = NODETYPE_SEGMENT_LIST
                            else:
                                NodeInfoDict['NodeType'] = NODETYPE_LEGACY

                        BatmanMacList = __GenerateGluonMACs(NodeInfoDict['MAC'])

                        if NodeVpnMAC not in BatmanMacList:
                            print(BatmanMacList)
                            if NodeInfoDict['NodeType'] == NODETYPE_SEGMENT_LIST:
                                BatmanMacList = __GenerateOldGluonMACs(NodeInfoDict['MAC'])

                                if NodeVpnMAC not in BatmanMacList:
                                    print('!!! Invalid Batman MAC schema!')
                                    NodeInfoDict['NodeType'] = None
                                else:
                                    print('+++ Old Gluon Version.')
                            else:
                                print('!!! Invalid Batman MAC schema!')
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
        print('... Node Info is consistent.')

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "getNodeInfos"
#
#    -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def getNodeInfos(FastdMAC,FastdIF,FastdMTU,BatmanIF):

    NodeJson = __InfoFromRespondd(FastdMAC,FastdIF)

    if NodeJson is None:
        print('++ No info via Respondd from VPN-Interface - trying via Batman TG ...')
        NodeMAC = __getNodeMACviaBatman(BatmanIF)

        if NodeMAC is not None:
            NodeJson = __InfoFromRespondd(NodeMAC,BatmanIF)

    if NodeJson is None:
        print('++ No info via Respondd!')
        NodeInfoDict = None
    else:
        NodeInfoDict = __AnalyseNodeJson(NodeJson,FastdMAC,FastdMTU)

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
            BatctlGwl = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'gwl'], stdout=subprocess.PIPE)
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



#-------------------------------------------------------------
# function "__SetupZipAreaData"
#
#     ZipFileDict -> Dictionary of ZIP-Area Files
#
#-------------------------------------------------------------
def __SetupZipAreaData(GitPath):

    print('Setting up ZIP-Area Data ...')

    ZipAreaFiles = glob(os.path.join(GitPath,'vpn*/zip-areas/?????_*.json'))
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
# function "__SetupZipGridData"
#
#     ZipGridDict -> Grid with ZIP-Codes
#
#-------------------------------------------------------------
def __SetupZipGridData(DatabasePath):

    print('Setting up ZIP-Grid Data ...')

    ZipGridDict = None
    FieldCount  = 0

    try:
        with open(os.path.join(DatabasePath,ZipGridName), mode='r') as ZipGridFile:
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

    print('... ZIP-Fields loaded: %d' % (FieldCount))
    return ZipGridDict



#-------------------------------------------------------------
# function "__GetZipSegmentFromGPS"
#
#     Get Segment from GPS using ZIP-Areas
#
#-------------------------------------------------------------
def __GetZipSegmentFromGPS(lon,lat,ZipAreaDict,ZipGridDict):

    ZipSegment = None

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
                    ZipSegment = ZipAreaDict[ZipCode]['Segment']
                    break

    return ZipSegment



#-----------------------------------------------------------------------
# function "GetGeoSegment"
#
#   Get Segment from Regions
#-----------------------------------------------------------------------
def GetGeoSegment(Location,GitPath,DatabasePath):

    print('Get Segment from Position ...',Location)

    ZipAreaDict = __SetupZipAreaData(GitPath)
    ZipGridDict = __SetupZipGridData(DatabasePath)

    GpsSegment = None
    ZipSegment = None

    if ZipAreaDict is None or ZipGridDict is None:
        print('!! No Region Data available !!!')
    else:
        if 'longitude' in Location and 'latitude' in Location:
            lon = Location['longitude']
            lat = Location['latitude']

            if LocationTemplate.match(str(lat)) and LocationTemplate.match(str(lon)):
                if lat < lon:
                    lon = Location['latitude']
                    lat = Location['longitude']

                while lat > 90.0:    # missing decimal separator
                    lat /= 10.0

                while lon > 70.0:    # missing decimal separator
                    lon /= 10.0

                GpsSegment = __GetZipSegmentFromGPS(lon,lat,ZipAreaDict,ZipGridDict)

            else:
                print('** Bad GPS Data:',str(lat),'|',str(lon))

        if 'zip' in Location:
            ZipCode = str(Location['zip'])[:5]
            print('... Checking ZIP-Code',ZipCode)

            if ZipTemplate.match(ZipCode):
                if ZipCode in ZipAreaDict:
                    ZipSegment = ZipAreaDict[ZipCode]['Segment']

                print('>>> GpsSegment / ZipSegment =',GpsSegment,'/',ZipSegment)

                if GpsSegment is not None:
                    if ZipSegment is not None and ZipSegment != GpsSegment:
                        print('!! Segment Mismatch GPS <> ZIP:',GpsSegment,'<>',ZipSegment)
                elif ZipSegment is not None:
                    GpsSegment = ZipSegment
                    print('++ Segment set by ZIP-Code:',ZipSegment)
            else:
                print('... invalid ZIP-Code Format:',ZipCode)

        if ZipSegment is None:
            print('>>> GpsSegment =',GpsSegment)

    return GpsSegment



#-----------------------------------------------------------------------
# function "GetSegment4Node"
#
#-----------------------------------------------------------------------
def GetSegment4Node(NodeInfo,GitPath,DatabasePath):

    NodeSegment = None

    if NodeInfo['Location'] is None:
        print('... no Location available ...')
    else:
        NodeSegment = GetGeoSegment(NodeInfo['Location'],GitPath,DatabasePath)
#        print('*** Location =',NodeInfo['Location'])

    if NodeSegment is None:
        NodeSegment = DEFAULT_SEGMENT
        print('... setting default Segment =',DEFAULT_SEGMENT)
    elif NodeInfo['NodeType'] == NODETYPE_SEGMENT_LIST and NodeSegment > 8:
        NodeSegment = DEFAULT_SEGMENT
        print('... replacing with default Segment =',DEFAULT_SEGMENT)

    return NodeSegment



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

    DnsKeyRing = None
    DnsUpdate  = None

    NeedCommit = False
    Action     = None
    ErrorCode  = 0


    #----- Analyse Situation -----
    NodeID     = NodeInfo['NodeID']
    NewSegment = NodeInfo['Segment']

    if NodeID in GitInfo['NodeID']:
        GitKey      = GitInfo['NodeID'][NodeID]['Key']
        GitSegment  = GitInfo['NodeID'][NodeID]['Segment']
        GitFixSeg   = GitInfo['NodeID'][NodeID]['fixed']
        GitNodeName = GitInfo['NodeID'][NodeID]['Hostname']

        print('*** NodeID in GitInfo:',GitSegment,'/',NodeID)

        if (PeerKey == GitKey) and (NewSegment == GitSegment):
            print('++ Node is already registered: vpn%02d / ffs-%s-%s\n' % (GitSegment,NodeID,GitKey[:12]))
            return 0

        if PeerKey != GitKey:
            Action = 'NEW_KEY'

            if PeerKey in GitInfo['Key']:
                print('++ Key already in use by other Node: vpn%02d / ffs-%s\n' % (GitInfo['NodeID'][GitInfo['Key'][PeerKey]]['Segment'],GitInfo['Key'][PeerKey]))
                return 0

        if NewSegment != GitSegment:
            if Action is None:
                Action = 'NEW_SEGMENT'
            else:
                Action = 'NEW_KEY + NEW_SEGMENT'

    else:  # NodeID is not in Git
        print('*** NodeID not in GitInfo:',NodeID)
        Action = 'NEW_NODE'

        GitKey      = None
        GitSegment  = None
        GitFixSeg   = None
        GitNodeName = None

        if PeerKey in GitInfo['Key']:
            print('++ Key already in use by other Node: vpn%02d / ffs-%s\n' % (GitInfo['NodeID'][GitInfo['Key'][PeerKey]]['Segment'],GitInfo['Key'][PeerKey]))
            return 0

        if NodeInfo['NodeType'] != NODETYPE_MTU_1340:
            print('!! Deprecated Firmware !!\n')

            if not NodeInfo['Updater']:
                print('++ Node will not be registered due to disabled Autoupdater!')
                return 0


    #----- Actions depending of Situation -----
    NewPeerFile    = 'vpn%02d/peers/ffs-%s' % (NewSegment,NodeInfo['NodeID'])
    NewPeerDnsName = 'ffs-%s-%s' % (NodeID,PeerKey[:12])
    NewPeerDnsIPv6 = '%s%d' % (SEGASSIGN_PREFIX,NewSegment)

    print('\n>>> Action:',Action)
    print('>>> New Peer Data:', NewPeerDnsName,'=', NewPeerFile,'->',NewPeerDnsIPv6)

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

        else:  # Git and DNS ready for registering node ...

            if GitKey is None:    # new Node
                if not os.path.exists(os.path.join(GitPath,NewPeerFile)):
                    WriteNodeKeyFile(os.path.join(GitPath,NewPeerFile), NodeInfo, None, PeerKey)
                    GitIndex.add([NewPeerFile])
                    DnsUpdate.replace(NewPeerDnsName, 120,'AAAA',NewPeerDnsIPv6)
                    print('*** New Node: vpn%02d / ffs-%s = \"%s\" (%s...)' % (NewSegment,NodeInfo['NodeID'],NodeInfo['Hostname'],PeerKey[:12]))
                    NeedCommit = True

                else:
                    print('... Key File was already added by other process.')

            else:    # existing Node
                OldPeerFile    = 'vpn%02d/peers/ffs-%s' % (GitSegment,NodeID)
                OldPeerDnsName = 'ffs-%s-%s' % (NodeID,GitKey[:12])
                print('>>> Existing Peer Data:', OldPeerDnsName,'=',OldPeerFile)

                if os.path.exists(os.path.join(GitPath,OldPeerFile)):
                    if NewSegment != GitSegment:
                        GitIndex.remove([OldPeerFile])
                        os.rename(os.path.join(GitPath,OldPeerFile), os.path.join(GitPath,NewPeerFile))
                        print('*** New Segment for existing Node: vpn%02d -> vpn%02d / %s = \"%s\"' % (GitSegment, NewSegment,NodeInfo['MAC'],NodeInfo['Hostname']))

                    if PeerKey != GitKey:
                        if NodeInfo['Hostname'] != GitNodeName:
                            GitFixSeg = None

                        WriteNodeKeyFile(os.path.join(GitPath,NewPeerFile), NodeInfo, GitFixSeg, PeerKey)
                        print('*** New Key for existing Node: vpn%02d / %s = \"%s\" -> %s...' % (NewSegment,NodeInfo['MAC'],NodeInfo['Hostname'],PeerKey[:12]))

                    GitIndex.add([NewPeerFile])
                    NeedCommit = True

                    if NewPeerDnsName != OldPeerDnsName:
                        DnsUpdate.delete(OldPeerDnsName,'AAAA')
                        DnsUpdate.add(NewPeerDnsName, 120,'AAAA',NewPeerDnsIPv6)
                    else:
                        DnsUpdate.replace(NewPeerDnsName, 120,'AAAA',NewPeerDnsIPv6)
                else:
                    print('... Key File was already changed by other process.')

            if NeedCommit:
                GitIndex.commit('Onboarding (%s) of %s = \"%s\" in Segment %02d' % (Action,NodeInfo['MAC'],NodeInfo['Hostname'],NewSegment))
                GitOrigin.config_writer.set('url',AccountsDict['Git']['URL'])
                print('... doing Git pull ...')
                GitOrigin.pull()
                print('... doing Git push ...')
                GitOrigin.push()
                print()

                if len(DnsUpdate.index) > 1:
                    dns.query.tcp(DnsUpdate,DnsServerIP)

                MailBody = 'Automatic Onboarding (%s) in Segment %02d:\n\n#MAC: %s\n#Hostname: %s\nkey \"%s\";\n' % (Action,NewSegment,NodeInfo['MAC'],NodeInfo['Hostname'],PeerKey)
                print(MailBody)

                __SendEmail('Onboarding of Node %s by ffs-Monitor' % (NodeInfo['Hostname']),MailBody,AccountsDict['KeyMail'])

    except:
        print('!!! ERROR on registering Node:',Action)
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
            print('Email was sent to',Account['MailTo'])

        except:
            print('!! ERROR on sending Email to',Account['MailTo'])

    return



#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
parser = argparse.ArgumentParser(description='Add or Modify Freifunk Node Registration')
parser.add_argument('--pid', dest='FASTDPID', action='store', required=True, help='Fastd PID')
parser.add_argument('--mtu', dest='FASTDMTU', action='store', required=True, help='Fastd MTU')
parser.add_argument('--fastd', dest='VPNIF', action='store', required=True, help='Fastd Interface')
parser.add_argument('--batman', dest='BATIF', action='store', required=True, help='Batman Interface')
parser.add_argument('--peerkey', dest='PEERKEY', action='store', required=True, help='Fastd PeerKey')
parser.add_argument('--gitrepo', dest='GITREPO', action='store', required=True, help='Git Repository with KeyFiles')
parser.add_argument('--data', dest='DATAPATH', action='store', required=True, help='Path to Databases')
parser.add_argument('--blacklist', dest='BLACKLIST', action='store', required=True, help='Blacklist Folder')

args = parser.parse_args()
PeerKey  = args.PEERKEY
FastdPID = int(args.FASTDPID)
FastdMTU = int(args.FASTDMTU)
RetCode  = 0

print('Onboarding of',PeerKey,'started with PID =',psutil.Process().pid,'/ MTU =',FastdMTU,'...')
BlacklistFile = os.path.join(args.BLACKLIST,PeerKey)

if os.path.exists(BlacklistFile):
    print('!! ERROR: Node is blacklisted:',PeerKey)
else:
    setBlacklistFile(BlacklistFile)

    AccountsDict = LoadAccounts(os.path.join(args.DATAPATH,AccountFileName))
    GitDataDict = LoadGitInfo(args.GITREPO)
    FastdStatusSocket = getFastdStatusSocket(FastdPID)

    if not os.path.exists(FastdStatusSocket) or AccountsDict is None or GitDataDict is None:
        print('!! ERROR: Accounts or Git-Data or Fastd Status Socket not available!')
    else:
        FastdMAC = getNodeFastdMAC(FastdStatusSocket)

        if FastdMAC is None:
            print('++ fastd-MAC is not available!')
        else:
            print('... fastd-MAC =',FastdMAC)

            BatmanVpnMAC = ActivateBatman(args.BATIF,args.VPNIF)    # using "batctl n" (Neighbor) to get VPN-MAC

            if BatmanVpnMAC is None:
                print('++ No valid Batman connection to Node!')
            elif BatmanVpnMAC != FastdMAC:
                print('++ Invalid Node due to mismatch of mesh-vpn MAC (Batman <> Fastd):',BatmanVpnMAC,'<>',FastdMAC)
            else:
                print('... Batman and fastd match on mesh-vpn MAC:',BatmanVpnMAC)
                NodeInfoDict = getNodeInfos(FastdMAC,args.VPNIF,FastdMTU,args.BATIF)    # Info of Node via Respondd

                if NodeInfoDict is None:
                    print('++ Node information not available or inconsistent!')
                elif BadNameTemplate.match(NodeInfoDict['Hostname']):
                    print('!!! Invalid Hostname: %s' % (NodeInfoDict['Hostname']))
                elif (NodeInfoDict['NodeType'] == NODETYPE_LEGACY) or (NodeInfoDict['Segment'] == 0):
                    print('!!! Legacy Node is not supported: %s\n' % (NodeInfoDict['Hostname']))
                else:
                    if (NodeInfoDict['Hardware'].lower().startswith('tp-link cpe') and
                        (NodeInfoDict['NodeType'] < NODETYPE_MTU_1340 or NodeInfoDict['GluonVer'][:14] < '1.4+2018-06-24')):
                        print('!! TP-Link CPE with outdated Firmware found: %s!!' % (NodeInfoDict['Hostname']))
                        TargetSegment = CPE_TEMP_SEGMENT
                    elif NodeInfoDict['Segment'] is None:
                        TargetSegment = getBatmanSegment(args.BATIF)    # meshing segment from "batctl gwl" (batman gateway list)
                    else:
                        TargetSegment = NodeInfoDict['Segment']

                    if TargetSegment is None:    # no specific segment required
                        TargetSegment = GetSegment4Node(NodeInfoDict, args.GITREPO, args.DATAPATH)
                    else:
                        print('>>> Node is meshing in segment %02d.' % (TargetSegment))

                    NodeInfoDict['Segment'] = TargetSegment    # where the node should be registered

                    RetCode = RegisterNode(PeerKey, NodeInfoDict, GitDataDict, args.GITREPO, args.DATAPATH, AccountsDict)

            DeactivateBatman(args.BATIF,args.VPNIF)

os.kill(FastdPID,signal.SIGUSR2)    # reset fastd connections

exit(RetCode)
