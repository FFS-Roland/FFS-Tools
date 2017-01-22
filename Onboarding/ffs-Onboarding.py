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
#      --blacklist = Folder for Blacklisting Files                                        #
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



#-------------------------------------------------------------
# Global Variables
#-------------------------------------------------------------

Key2MacDict = {}    # PeerKey -> {'SegDir', 'KeyFileName', 'PeerMAC'}
Mac2KeyDict = {}    # PeerMAC -> {'SegDir', 'KeyFileName', 'PeerKey'}



#-----------------------------------------------------------------------
# function "getProcessID"
#
#-----------------------------------------------------------------------
def getProcessID(segment):
    pid = 0
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name',"cmdline"])
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['name'] == 'fastd':
                config = pinfo['cmdline'][pinfo['cmdline'].index('--config')+1]
                if os.path.dirname(config).rsplit('/',1)[1] == segment:
                    pid = pinfo['pid']
                    break
    return pid


#-----------------------------------------------------------------------
# function "getSocket"
#
#-----------------------------------------------------------------------
def getSocket(pid):
    fastdSocket = ''
    p = psutil.Process(pid)
    try:
        connections = p.get_connections(kind='unix')
    except:
        pass
    try:
        connections = p.connections(kind='unix')
    except:
        pass

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
    MeshMAC = ''
    Retries = 3

    while(MeshMAC == '' and Retries > 0):
        Retries -= 1
        StatusData = ''
        time.sleep(1)

        try:
            FastdLiveStatus = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
            FastdLiveStatus.connect(FastdStatusSocket)

            while(True):
                tmpData = FastdLiveStatus.recv(4096).decode('utf-8')
                if tmpData == '':
                    break;

                StatusData += tmpData

            FastdLiveStatus.close()

            if StatusData != '':
                FastdStatusJson = json.loads(StatusData)

                if PeerKey in FastdStatusJson['peers']:
                    if not FastdStatusJson['peers'][PeerKey]['connection'] is None:
                        if 'mac_addresses' in FastdStatusJson['peers'][PeerKey]['connection']:
                            for MeshMAC in FastdStatusJson['peers'][PeerKey]['connection']['mac_addresses']:
                                break
        except:
            MeshMAC = ''

    return MeshMAC


#-----------------------------------------------------------------------
# function "getNodeInfos"
#
#-----------------------------------------------------------------------
def getNodeInfos(LLA):
    NodeJson = {}
    Retries = 3

    while(NodeJson == {} and Retries > 0):
        Retries -= 1
        try:
            NodeHTTP = urllib.request.urlopen('http://['+NodeLLA+']/cgi-bin/nodeinfo')
            NodeJson = json.loads(NodeHTTP.read().decode('utf-8'))
            NodeHTTP.close()
        except:
            time.sleep(1)
            NodeJson = {}
            continue

    return NodeJson


#-----------------------------------------------------------------------
# function "checkDNS"
#
#-----------------------------------------------------------------------
def checkDNS(NodeID):
    SegFromDNS = None
    DnsServer = 'dns1.lihas.de'
    resolver = dns.resolver.Resolver()
    server_ip = resolver.query('%s.'%(DnsServer),'a')[0].to_text()

    resolver.nameservers = [server_ip]

    Hostname = NodeID + '.segassign.freifunk-stuttgart.de.'
    print('Hostname =',Hostname)

    try:
        aaaaRecs = resolver.query(Hostname,'aaaa')

        for rec in aaaaRecs:
            if rec.to_text()[:14] == '2001:2:0:711::':
                SegFromDNS = 'vpn'+rec.to_text()[14:].zfill(2)

    except:
        SegFromDNS = None

    return SegFromDNS


#-----------------------------------------------------------------------
# function "LoadKeyData"
#
#-----------------------------------------------------------------------
def LoadKeyData(Path):

    global Key2MacDict
    global Mac2KeyDict

    try:
        LockFile = open(os.path.join(Path,'.KeyDB.lock'), mode='w+')
        fcntl.lockf(LockFile,fcntl.LOCK_EX)
        print('Reading Fastd Databases json-Files ...')

        Key2MacJsonFile = open(os.path.join(Path,'Key2Mac.json'), mode='r')
        Key2MacDict = json.load(Key2MacJsonFile)
        Key2MacJsonFile.close()

        Mac2KeyJsonFile = open(os.path.join(Path,'Mac2Key.json'), mode='r')
        Mac2KeyDict = json.load(Mac2KeyJsonFile)
        Mac2KeyJsonFile.close()

    except:
        print('\n!! Error on Reading Fastd Database json-Files!\n')

    finally:
        fcntl.lockf(LockFile,fcntl.LOCK_UN)
        LockFile.close()

    return


#-----------------------------------------------------------------------
# function "getMeshSegment"
#
#-----------------------------------------------------------------------
def getMeshSegment(NodeAddresses,BatmanIF,FastdIF):

    MeshSeg = ''

    for NodeIPv6 in NodeAddresses:
        if NodeIPv6[0:12] == 'fd21:b4dc:4b':
            MeshSeg = NodeIPv6[12:14]
            break

    if MeshSeg == '':   # No usable IPv6 Address on Status Page of Node
        Retries = 20

        try:
            subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','del',FastdIF])
            subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','add',FastdIF])
            subprocess.run(['/sbin/ip','link','set',BatmanIF,'up'])
        except:
            pass

        while(MeshSeg == '' and Retries > 0):
            Retries -= 1
            time.sleep(1)

            try:
                BatctlGwl = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'gwl'], stdout=subprocess.PIPE)
                gwl = BatctlGwl.stdout.decode('utf-8')

                for Gateway in gwl.split('\n'):
                    if Gateway[3:10] == '02:00:3':
                        MeshSeg = Gateway[12:14]
                        break
                    elif Gateway[3:12] == '02:00:0a:':
                        MeshSeg = Gateway[15:17]
                        break
            except:
                MeshSeg = ''

    if MeshSeg == '':
        Segment = None
    else:
        Segment = 'vpn'+MeshSeg

    return Segment


#-----------------------------------------------------------------------
# function "__TestAddNode"
#
#-----------------------------------------------------------------------
def __TestAddNode(NodeJson,Segment,PeerKey,LogPath):

    if Segment is None:
        Segment = 'vpn99'

    try:
        KeyFile = open(os.path.join(LogPath,'new_peers','ffs-'+NodeJson['node_id']), mode='w')
        KeyFile.write('#MAC: %s\n#Hostname: %s\n#Segment: %s\nkey \"%s\";' %
                      (NodeJson['network']['mac'],NodeJson['hostname'],Segment,PeerKey))
        KeyFile.close()
    except:
        return False

    return True


#-----------------------------------------------------------------------
# function "__TestDelNode"
#
#-----------------------------------------------------------------------
def __TestDelNode(NodeJson,Segment,PeerKey,LogPath):

    try:
        KeyFile = open(os.path.join(LogPath,'old_peers','ffs-'+NodeJson['node_id']), mode='w')
        KeyFile.write('#MAC: %s\n#Hostname: %s\n#Segment: %s\nkey \"%s\";' %
                      (NodeJson['network']['mac'],NodeJson['hostname'],Segment,PeerKey))
        KeyFile.close()
    except:
        return False

    return True


#-----------------------------------------------------------------------
# function "RegisterNode"
#
#-----------------------------------------------------------------------
def RegisterNode(NodeJson,Segment,PeerKey,GitRepo):
    if Segment == '':
        Segment = '99'

    try:
        KeyFile = open(os.path.join(GitRepo,'vpn'+Segment,'peers','ffs-'+NodeJson['node_id']), mode='w')
        KeyFile.write('#MAC: %s\n#Hostname: %s\nkey \"%s\";' %
                      (NodeJson['network']['mac'],NodeJson['hostname'],PeerKey))
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
    except:
        pass

    return


#-----------------------------------------------------------------------
# function "detachPeers"
#
#-----------------------------------------------------------------------
def detachPeers(pid):

    os.kill(pid,signal.SIGHUP)
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

PID = getProcessID(args.VPNIF)
if PID == 0:
    exit(1)

if not os.path.exists(args.BLACKLIST+'/'+args.PEERKEY):
    PeerKey = args.PEERKEY
    FastdStatusSocket = getSocket(PID)

    if os.path.exists(FastdStatusSocket):
        MeshMAC = getMeshMAC(FastdStatusSocket)

        if MeshMAC != '':
            NIC = args.VPNIF
            NodeLLA = 'fe80::' + hex(int(MeshMAC[0:2],16) ^ 0x02)[2:] + MeshMAC[3:8]+'ff:fe'+MeshMAC[9:14]+MeshMAC[15:17]+'%'+NIC
            NodeJson = getNodeInfos(NodeLLA)

            if 'node_id' in NodeJson and 'network' in NodeJson and 'mac' in NodeJson['network']:
            #----- Required Data of Node is available -----
                LoadKeyData(args.JSONPATH)
                PeerMAC = NodeJson['network']['mac']
                DnsSegment  = checkDNS('ffs-'+NodeJson['node_id']+'-'+PeerKey[:12])    # -> 'vpn??'
                MeshSegment = getMeshSegment(NodeJson['network']['addresses'],args.BATIF,args.VPNIF)

                if DnsSegment is None:  # Node is not registered in DNS

                    if PeerKey in Key2MacDict:
                        print('++ Key is already in use:',PeerKey,NodeJson['node_id'],'/',NodeJson['network']['mac'],'->',
                              Key2MacDict[PeerKey]['PeerMAC'],'=',Key2MacDict[PeerKey]['SegDir'],'/',Key2MacDict[PeerKey]['KeyFileName'])

                    if PeerMAC in Mac2KeyDict:
                        print('++ MAC is already in use:',PeerKey,NodeJson['node_id'],'/',PeerMAC,'->',
                              Mac2KeyDict[PeerMAC]['SegDir'],'/',Mac2KeyDict[PeerMAC]['KeyFileName'],'=',Mac2KeyDict[PeerMAC]['PeerKey'])


#                    if RegisterNode(NodeJson,MeshSegment,PeerKey,args.GITREPO):
                    if __TestAddNode(NodeJson,MeshSegment,PeerKey,args.JSONPATH):
                        setBlacklistFile(os.path.join(args.BLACKLIST,PeerKey))

                else:  # Node is already registered in DNS
                    if PeerKey in Key2MacDict:

                        if Key2MacDict['PeerMAC'] != PeerMAC:
                            print('!! Mismatch between DNS and Git:',PeerKey,'->',Key2MacDict['PeerMAC'],'<>',PeerMAC)
                        else:  # DNS == Git
                            if MeshSegment != DnsSegment:
                                print('++ Node must be moved to other Segment:',PeerKey,'=',PeerMAC,'->',MeshSegment,'<>',DnsSegment)
                            else:
                                setBlacklistFile(os.path.join(args.BLACKLIST,PeerKey))

                    else:  # Node is in DNS but not in Git
                        print('++ DNS is faster than Git:',PeerKey,'=',PeerMAC)

#else:
#    print('++ ERROR: This must not happen!',args.PEERKEY)

detachPeers(PID)
exit(0)
