#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  ffs-Onboarding.py                                                                      #
#                                                                                         #
#  Automatically registering unknown Nodes, and updating existing but changed Nodes.      #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#      --fastd     = fastd-Interface (e.g. vpn00)                                         #
#      --batman    = batman-Interface (e.g. bat00)                                        #
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
import fcntl
import argparse


#----- Json-File with needed Accounts -----
AccountFileName  = '.Accounts.json'




#-----------------------------------------------------------------------
# function "getFastdProcessID"
#
#    > FastdInterface = 'vpn??'
#-----------------------------------------------------------------------
def getFastdProcessID(FastdInterface):

    pid = None
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name',"cmdline"])
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['name'] == 'fastd':
                config = pinfo['cmdline'][pinfo['cmdline'].index('--config')+1]
                if os.path.dirname(config).rsplit('/',1)[1] == FastdInterface:
                    pid = pinfo['pid']
                    break
    return pid



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
    Retries = 3

    while MeshMAC is None and Retries > 0:
        Retries -= 1
        StatusData = ''
        time.sleep(1)

        try:
            FastdLiveStatus = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
            FastdLiveStatus.connect(FastdStatusSocket)

            while True:
                tmpData = FastdLiveStatus.recv(4096).decode('utf-8')
                if tmpData == '':
                    break;

                StatusData += tmpData

            FastdLiveStatus.close()

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
def InfoFromGluonNodeinfoPage(NodeLLA):

    NodeInfoDict = None

    try:
        NodeHTTP = urllib.request.urlopen('http://['+NodeLLA+']/cgi-bin/nodeinfo',timeout=10)
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
                    if NodeIPv6[0:12] == 'fd21:b4dc:4b':
                        if NodeIPv6[12:14] == '1e':
                             NodeInfoDict['Segment'] = 'vpn00'
                        else:
                            NodeInfoDict['Segment'] = 'vpn'+NodeIPv6[12:14]
                        break
                print('>>> Segment =',NodeInfoDict['Segment'])

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "InfoFromGluonStatusPage"
#
#    must be used on Gluon >= v2016.1
#
#  -> NodeInfoDict {'NodeType','NodeID','MAC','Hostname','Segment'}
#-----------------------------------------------------------------------
def InfoFromGluonStatusPage(NodeLLA):

    NodeInfoDict = None
    NodeHTML = None

    try:
        NodeHTTP = urllib.request.urlopen('http://['+NodeLLA+']/cgi-bin/status',timeout=10)
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
            else:
                NodeInfoDict['Segment'] = 'vpn'+NodeHTML[pStart:pStart+2]

        print('>>> Segment =',NodeHTML[pStart:pStop])

    return NodeInfoDict



#-----------------------------------------------------------------------
# function "getNodeInfos"
#
#-----------------------------------------------------------------------
def getNodeInfos(NodeLLA):

    NodeInfoDict = None
    NodeHTML = None
    Retries = 3

    while NodeHTML is None and Retries > 0:
        print('Connecting to http://['+NodeLLA+'] ...')
        Retries -= 1
        try:
            NodeHTTP = urllib.request.urlopen('http://['+NodeLLA+']/',timeout=10)
            NodeHTML = NodeHTTP.read().decode('utf-8')
            NodeHTTP.close()
        except:
            NodeHTML = None
            time.sleep(1)
            pass

    if NodeHTML is not None:
        if NodeHTML[:15] == '<!DOCTYPE html>':
            print('... new Gluon ...')
            NodeInfoDict = InfoFromGluonNodeinfoPage(NodeLLA)
        else:
            print('... old Gluon ...')
            NodeInfoDict = InfoFromGluonStatusPage(NodeLLA)

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

    Hostname = NodeID + '.segassign.freifunk-stuttgart.de.'
    print('DNS Query =',Hostname)

    try:
        aaaaRecs = DnsResolver.query(Hostname,'aaaa')

        for IPv6 in aaaaRecs:
            if IPv6.to_text()[:14] == '2001:2:0:711::':
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
        print('... Reading Fastd Key Database json-File ...')

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
# function "getBatmanSegment"
#
#-----------------------------------------------------------------------
def getBatmanSegment(BatmanIF,FastdIF):

    Retries = 20
    BatSeg = None

    try:
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','del',FastdIF])
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','add',FastdIF])
        subprocess.run(['/sbin/ip','link','set',BatmanIF,'up'])
    except:
        pass

    while(Retries > 0):
        Retries -= 1
        time.sleep(1)

        try:
            BatctlGwl = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'gwl'], stdout=subprocess.PIPE)
            gwl = BatctlGwl.stdout.decode('utf-8')

            for Gateway in gwl.split('\n'):
                if Gateway[3:10] == '02:00:3':
                    BatSeg = 'vpn'+Gateway[12:14]
                    Retries = 0
                    break
                elif Gateway[3:12] == '02:00:0a:':
                    BatSeg = 'vpn'+Gateway[15:17]
                    Retries = 0
                    break
        except:
            BatSeg = None

    return BatSeg



#-----------------------------------------------------------------------
# function "__TestAddNode"
#
#-----------------------------------------------------------------------
def __TestAddNode(NodeInfo,PeerKey,LogPath):

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



#-----------------------------------------------------------------------
# function "detachPeers"
#
#-----------------------------------------------------------------------
def detachPeers(pid):

    os.kill(pid,signal.SIGHUP)
    time.sleep(1)
    os.kill(pid,signal.SIGUSR2)

    return



#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
parser = argparse.ArgumentParser(description='Add or Modify Freifunk Node Registration')
parser.add_argument('--fastd', dest='VPNIF', action='store', required=True, help='Fastd Interface = Segment')
parser.add_argument('--batman', dest='BATIF', action='store', required=True, help='Batman Interface')
parser.add_argument('--peerkey', dest='PEERKEY', action='store', required=True, help='Fastd PeerKey')
parser.add_argument('--gitrepo', dest='GITREPO', action='store', required=True, help='Git Repository with KeyFiles')
parser.add_argument('--json', dest='JSONPATH', action='store', required=True, help='Path to Database with Keys and MACs')
parser.add_argument('--blacklist', dest='BLACKLIST', action='store', required=True, help='Blacklist Folder')

args = parser.parse_args()
PeerKey = args.PEERKEY

print('Onboarding of',PeerKey,'started with PID =',psutil.Process().pid,'...')
FastdPID = getFastdProcessID(args.VPNIF)

if FastdPID is None:
    print('!! FATAL ERROR: Fastd PID not available or Fastd not running!')
    exit(1)


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
            NodeLLA = 'fe80::' + hex(int(MeshMAC[0:2],16) ^ 0x02)[2:] + MeshMAC[3:8]+'ff:fe'+MeshMAC[9:14]+MeshMAC[15:17]+'%'+args.VPNIF
            NodeInfo = getNodeInfos(NodeLLA)

            if NodeInfo is not None:
            #----- Required Data of Node is available -----
                PeerMAC = NodeInfo['MAC']

                if NodeInfo['Segment'] is None:
                    print('... getBatmanSegment ...')
                    NodeInfo['Segment'] = getBatmanSegment(args.BATIF,args.VPNIF)

                DnsSegment  = checkDNS('ffs-'+NodeInfo['NodeID']+'-'+PeerKey[:12],AccountsDict['DNS']['Server'])    # -> 'vpn??'
                print('>> DNS / Mesh =',DnsSegment,'/',NodeInfo['Segment'])

                if DnsSegment is None:  # Node is not registered in DNS

                    if PeerKey[:12] in KeyDataDict['Key2Mac']:
                        print('++ Key is already in use:',NodeInfo['NodeID'],'/',PeerMAC,'->',
                              KeyDataDict['Key2Mac'][PeerKey[:12]]['PeerMAC'],'=',KeyDataDict['Key2Mac'][PeerKey[:12]]['SegDir'],'/',KeyDataDict['Key2Mac'][PeerKey[:12]]['KeyFile'])

                    if PeerMAC in KeyDataDict['Mac2Key']:
                        print('++ MAC is already in use:',NodeInfo['NodeID'],'/',PeerMAC,'->',
                              KeyDataDict['Mac2Key'][PeerMAC]['SegDir'],'/',KeyDataDict['Mac2Key'][PeerMAC]['KeyFile'],'=',KeyDataDict['Mac2Key'][PeerMAC]['PeerKey']+'...')


#                   RegisterNode(NodeInfo,PeerKey,args.GITREPO)
                    __TestAddNode(NodeInfo,PeerKey,args.JSONPATH)

                else:  # Node is already registered in DNS
                    if PeerKey[:12] in KeyDataDict['Key2Mac']:

                        if KeyDataDict['Key2Mac'][PeerKey[:12]]['PeerMAC'] != PeerMAC:
                            print('!! MAC Mismatch between Git and Peer:',KeyDataDict['Key2Mac'][PeerKey[:12]]['PeerMAC'],'<>',PeerMAC)
                        else:  # DNS == Git
                            if NodeInfo['Segment'] != DnsSegment:
                                print('++ Node must be moved to other Segment:',PeerMAC,'/',DnsSegment,'->',NodeInfo['Segment'])
                            else:
                                print('++ Node is already registered:',PeerMAC,'/',DnsSegment)

                    else:  # Node is in DNS but not in Git
                        print('++ DNS is faster than Git:',PeerKey,'=',PeerMAC)

                #endif (Handling of Registration)

            else:
                print('++ Node status information not available!')

        else:
            print('++ MeshMAC (or KeyDataDict) is not available!',MeshMAC)

    else:
        print('!! ERROR: Accounts or Fastd Status Socket not available!')

else:
    print('!! ERROR: Node is blacklisted:',PeerKey)


detachPeers(FastdPID)
exit(0)
