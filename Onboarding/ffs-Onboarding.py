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
#      --blacklist = Folder for Blacklisting Files                                        #
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
import argparse


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
    SegFromDNS = ''
#    DnsServer = 'dns1.lihas.de'
    resolver = dns.resolver.Resolver()
#    server_ip = resolver.query('%s.'%(DnsServer),'a')[0].to_text()

#    resolver.nameservers = [server_ip]

    Hostname = NodeID + '.segassign.freifunk-stuttgart.de.'
    print('Hostname =',Hostname)

    try:
        aaaaRecs = resolver.query(Hostname,'aaaa')

        for rec in aaaaRecs:
            if rec.to_text()[:14] == '2001:2:0:711::':
                SegFromDNS = rec.to_text()[14:].zfill(2)

    except:
        SegFromDNS = ''

    return SegFromDNS


#-----------------------------------------------------------------------
# function "getBatmanSegment"
#
#-----------------------------------------------------------------------
def getBatmanSegment(BatmanIF,FastdIF):
    Segment = ''
    Retries = 20

    try:
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','del',FastdIF])
        subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'if','add',FastdIF])
        subprocess.run(['/sbin/ip','link','set',BatmanIF,'up'])
    except:
        pass

    while(Segment == '' and Retries > 0):
        Retries -= 1
        time.sleep(1)

        try:
            BatctlGwl = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'gwl'], stdout=subprocess.PIPE)
            gwl = BatctlGwl.stdout.decode('utf-8')

            for Gateway in gwl.split('\n'):
                if Gateway[3:10] == '02:00:3':
                    Segment = Gateway[12:14]
                    break
                elif Gateway[3:12] == '02:00:0a:':
                    Segment = Gateway[15:17]
                    break

        except:
            Segment = ''

    return Segment


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

            if 'node_id' in NodeJson:
                Segment = checkDNS('ffs-'+NodeJson['node_id']+'-'+PeerKey[:12])

                if Segment == '':  # Node is not registered
                    for NodeAddr in NodeJson['network']['addresses']:
                        if NodeAddr[0:12] == 'fd21:b4dc:4b':
                            Segment = NodeAddr[12:14]
                            break

                    if Segment == '':   # No IPv6 Address on Status Page of Node
                        Segment = getBatmanSegment(args.BATIF,args.VPNIF)

                    if RegisterNode(NodeJson,Segment,PeerKey,args.GITREPO):
                        setBlacklistFile(os.path.join(args.BLACKLIST,PeerKey))

                else:  # Node is already registered
                    setBlacklistFile(os.path.join(args.BLACKLIST,PeerKey))

# else:
#   print('++ ERROR: This must not happen!',args.PEERKEY)

detachPeers(PID)
exit(0)
