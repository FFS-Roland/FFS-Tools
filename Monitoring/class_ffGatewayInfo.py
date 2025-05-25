#!/usr/bin/python3

#################################################################################################
#                                                                                               #
#   class_ffGatewayInfo.py                                                                      #
#                                                                                               #
#   Analyse fastd-Keys from Git and fastd-Status-Info from Gateways.                            #
#                                                                                               #
#                                                                                               #
#   Needed json-Files:                                                                          #
#                                                                                               #
#       fastd/vpn??.json     -> fastd-Keys (live Data) from Gateways                            #
#                                                                                               #
#################################################################################################
#                                                                                               #
#   Copyright (C) 2025  Freifunk Stuttgart e.V.                                                 #
#                                                                                               #
#   This program is free software: you can redistribute it and/or modify it under the terms     #
#   of the GNU General Public License as published by the Free Software Foundation, either      #
#   version 3 of the License, or (at your option) any later version.                            #
#                                                                                               #
#   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;   #
#   without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   #
#   See the GNU General Public License for more details.                                        #
#                                                                                               #
#   You should have received a copy of the GNU General Public License along with this program.  #
#   If not, see <https://www.gnu.org/licenses/>.                                                #
#                                                                                               #
#################################################################################################

import os
import subprocess
import socket
import urllib.request
import time
import datetime
import calendar
import json
import re
import fcntl
import git
import random

import dns.resolver
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.update

from dns.rdataclass import *
from dns.rdatatype import *

from scapy.all import conf, sr1, IP, ICMP, TCP

from glob import glob

from class_ffDHCP import *
from class_ffDnsServer import *



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

MaxStatusAge        = 15 * 60        # 15 Minutes (in Seconds)
MinGatewayCount     = 1              # minimum number of Gateways per Segment

SegAssignIPv4Prefix = '198.18.190.'
SegAssignIPv6Prefix = '2001:2:0:711::'

GwIgnoreList        = [ 'gw04n03','gw05n01','gw05n08','gw05n09' ]
SegmentIgnoreList   = [ 0, 26 ]

InternetTestTargets = ['www.google.de','www.youtube.de','www.ebay.de','www.wikipedia.de','www.heise.de']

DnsIP4SegTemplate   = re.compile('^'+SegAssignIPv4Prefix+'[0-9]{1,2}$')
DnsIP6SegTemplate   = re.compile('^'+SegAssignIPv6Prefix+'(([0-9a-f]{1,4}:){1,2})?[0-9]{1,2}$')

DnsNodeTemplate     = re.compile('^ffs-[0-9a-f]{12}-[0-9a-f]{12}$')

GwSegGroupTemplate  = re.compile('^gw[0-6][0-9](s[0-9]{2})$')
GwInstanceTemplate  = re.compile('^gw[0-6][0-9](n[0-9]{2})$')
GwSegmentTemplate   = re.compile('^gw[0-6][0-9](n[0-9]{2})(s[0-9]{2})$')
GwMacTemplate       = re.compile('^02:00:3[1-9](:[0-9]{2}){3}')

MacAdrTemplate      = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
NodeIdTemplate      = re.compile('^[0-9a-f]{12}$')

PeerTemplate        = re.compile('^ffs-[0-9a-f]{12}')

SegmentTemplate     = re.compile('^[0-9]{2}$')
KeyDirTemplate      = re.compile('^vpn[0-9]{2}$')

FastdKeyTemplate    = re.compile('^[0-9a-f]{64}$')
FastdFileTemplate   = re.compile('^vp.[0-6][0-9]\.json$')





class ffGatewayInfo:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self, GitPath, DnsAccDicts):

        # public Attributes
        self.Alerts       = []           # List of  Alert-Messages
        self.AnalyseOnly  = False        # Blocking active Actions due to inconsistent Data

        # private Attributes
        self.__GitPath     = GitPath
        self.__DnsAccDicts = DnsAccDicts # DNS Accounts

        self.__GatewayDict = {}          # GatewayDict[GwInstanceName] -> IPs, DnsSegments, BatmanSegments
        self.__SegmentDict = {}          # SegmentDict[SegmentNumber]  -> GwGitNames, GwDnsNames, GwBatNames, GwIPs
        self.__GwAliasDict = {}          # GwAliasDict[LegacyName]     -> current new Gateway
        self.__FastdKeyDict = {}         # FastdKeyDict[FastdKey]      -> KeyDir,KeyFile,SegMode,PeerMAC,PeerName,VpnMAC,Timestamp,Dns4Seg,Dns6Seg
        self.__PeerDnsDict = {}          # PeerDnsDict[DNS-ID]         -> FastdKey

        # Initializations
        socket.setdefaulttimeout(5)
        self.__GitPullPeersFFS()

        self.__GetGatewaysFromGit()
        self.__GetGatewaysFromDNS()
        self.__GetGatewaysFromBatman()
        return



    #-----------------------------------------------------------------------
    # private function "__alert"
    #
    #   Store and print Message for Alert
    #
    #-----------------------------------------------------------------------
    def __alert(self, Message):

        self.Alerts.append(Message)
        print(Message)
        return



    #=======================================================================
    # private init function "__GitPullPeersFFS"
    #
    #   Git Pull on Repository "peers-ffs"
    #
    #-----------------------------------------------------------------------
    def __GitPullPeersFFS(self):

        print('Git Pull on Repository \"peers-ffs\" ...')

        GitLockName = os.path.join('/tmp','.'+os.path.basename(self.__GitPath)+'.lock')

        try:
            LockFile = open(GitLockName, mode='w+')
            fcntl.lockf(LockFile,fcntl.LOCK_EX)
            GitRepo   = git.Repo(self.__GitPath)
            GitOrigin = GitRepo.remotes.origin

            if not GitRepo.is_dirty():
                GitOrigin.pull()
            else:
                self.AnalyseOnly = True
                self.__alert('!! Git Repository is dirty - switched to analyse only mode!')

        except:
            self.__alert('!! Fatal ERROR on accessing Git Repository!')
        finally:
            del GitOrigin
            del GitRepo

            fcntl.lockf(LockFile,fcntl.LOCK_UN)
            LockFile.close()

        print('... done.\n')
        return



    #=======================================================================
    # private init function "__GetGatewaysFromGit"
    #
    #   Load and analyse Gateway-Files from Git
    #
    #-----------------------------------------------------------------------
    def __GetGatewaysFromGit(self):

        print('Loading Gateways from Git ...')

        GwFileList = glob(os.path.join(self.__GitPath,'vpn*/bb/gw*'))

        for KeyFilePath in GwFileList:
            Segment  = int(os.path.dirname(KeyFilePath).split("/")[-2][3:])
            FileName = os.path.basename(KeyFilePath)

            if (Segment == 0) or (Segment > 64):
                print('!! Illegal Segment: %0d' % (Segment))
                continue

            if Segment not in self.__SegmentDict:
                self.__SegmentDict[Segment] = {
                    'GwGitNames':[],
                    'GwDnsNames':[],
                    'GwBatNames':[],
                    'GwIPs':[]
                }

            if GwSegmentTemplate.match(FileName):
                if int(FileName.split('s')[1]) == Segment:
                    self.__SegmentDict[Segment]['GwGitNames'].append(FileName.split('s')[0])
                else:
                    print('++ Invalid File Name in Git: %s' % (KeyFilePath))
            else:
                print('!! Bad File in Git: %s' % (KeyFilePath))

        print('... done.\n')
        return



    #==========================================================================
    # private init function "__GetGatewaysFromDNS"
    #
    #   Result = __GatewayDict[GwInstanceName] -> IPs and Segments for the GW
    #
    #--------------------------------------------------------------------------
    def __GetGatewaysFromDNS(self):

        FreifunkGwDomain = self.__DnsAccDicts[0]['GwDomain']

        print('Checking DNS for Gateway Instances: %s ...' % (FreifunkGwDomain))

        GwDnsServer = ffDnsServer(FreifunkGwDomain, self.__DnsAccDicts[0])
        dicGwIPs = GwDnsServer.GetDnsZone()

        if dicGwIPs is None:
            print('++ DNS Zone \"%s\" not available !!' % (FreifunkGwDomain))
            self.AnalyseOnly = True
        else:
            self.AnalyseOnly = GwDnsServer.ReadOnly

            #----- get Gateways from Zone File -----
            for GwName in dicGwIPs:
                if GwInstanceTemplate.match(GwName):      # n
                    self.__GatewayDict[GwName] = { 'IPs': dicGwIPs[GwName], 'DnsSegments': [], 'BatmanSegments': [] }
                elif GwSegGroupTemplate.match(GwName):    # s
                    Segment = int(GwName[5:])

                    if Segment == 0 or Segment > 64:
                        continue    # >>> Onboarder

                    if Segment not in self.__SegmentDict:
                        print('!! Segment in DNS but not in Git: %s' % (GwName))

                        self.__SegmentDict[Segment] = {
                            'GwGitNames':[],
                            'GwDnsNames':[],
                            'GwBatNames':[],
                            'GwIPs':[]
                        }

                    self.__SegmentDict[Segment]['GwIPs'] += dicGwIPs[GwName]

            #----- setting up GwIP to GwInstanceName -----
            Ip2GwDict = {}

            for GwName in self.__GatewayDict:
                for GwIP in self.__GatewayDict[GwName]['IPs']:
                    if GwIP not in Ip2GwDict:
                        Ip2GwDict[GwIP] = GwName
                    else:
                        if Ip2GwDict[GwIP][:4] == GwName[:4] and len(GwName) != len(Ip2GwDict[GwIP]):
                            print('++ Gateway Alias: %s = %s = %s' % (GwIP,GwName, Ip2GwDict[GwIP]))

                            if len(GwName) > len(Ip2GwDict[GwIP]):    # longer name is new name
                                self.__GwAliasDict[Ip2GwDict[GwIP]] = GwName
                                Ip2GwDict[GwIP] = GwName
                            else:
                                self.__GwAliasDict[GwName] = Ip2GwDict[GwIP]
                        else:
                            print('!! Duplicate Gateway IP: %s = %s <> %s' % (GwIP,Ip2GwDict[GwIP],GwName))

            for GwName in self.__GwAliasDict:
                del self.__GatewayDict[GwName]

            print()
            for GwName in sorted(self.__GatewayDict):
                print(GwName.ljust(7),'=',self.__GatewayDict[GwName]['IPs'])

            print()

            for GwIP in sorted(Ip2GwDict):
                if '.' in GwIP:
                    print('%-15s -> %s' % (GwIP, Ip2GwDict[GwIP]))

            print()
            for GwIP in sorted(Ip2GwDict):
                if ':' in GwIP:
                    print('%-36s -> %s' % (GwIP, Ip2GwDict[GwIP]))

            #----- setting up Segment to GwInstanceNames -----
            print('\nChecking Segments for Gateways in DNS: %s ...\n' % (FreifunkGwDomain))
            for Segment in sorted(self.__SegmentDict.keys()):
#                print('>>>',Segment,'->',self.__SegmentDict[Segment]['GwIPs'])

                for GwIP in self.__SegmentDict[Segment]['GwIPs']:
                    if GwIP in Ip2GwDict:
                        GwName = Ip2GwDict[GwIP]

                        if GwName not in self.__SegmentDict[Segment]['GwDnsNames']:
                            self.__SegmentDict[Segment]['GwDnsNames'].append(GwName)

                            if Segment not in self.__GatewayDict[GwName]['DnsSegments']:
                                self.__GatewayDict[GwName]['DnsSegments'].append(Segment)
                            else:
                                self.__alert('!! DNS entries are inconsistent: %s -> %02d' % (GwName, Segment))
                    else:
                        self.__alert('!! Unknown Gateway IP: %s' % (GwIP))

                if len(self.__SegmentDict[Segment]['GwGitNames']) > 0:
                    if len(self.__SegmentDict[Segment]['GwDnsNames']) < MinGatewayCount:
                        self.__alert('!! Too few Gateways in Segment %02d: %s' % (Segment, self.__SegmentDict[Segment]['GwDnsNames']))
                    else:
                        print('Seg.%02d -> %s' % (Segment, sorted(self.__SegmentDict[Segment]['GwDnsNames'])))
                else:
                    self.__alert('!! Gateway in DNS but not in Git for Segment %02d: %s' % (Segment, self.__SegmentDict[Segment]['GwDnsNames']))

            print()
            for GwName in sorted(self.__GatewayDict):
                print(GwName.ljust(7), '->', sorted(self.__GatewayDict[GwName]['DnsSegments']))

        print('\n... done.\n')
        return



    #--------------------------------------------------------------------------
    # private function "__GetGwMACfromBatmanTG"
    #
    #    Returns Gateway Name via MAC from global Translation Table
    #
    #--------------------------------------------------------------------------
    def __GetGwMACfromBatmanTG(self, Segment, badGwMAC):

        BatctlTgCmd  = ('/usr/sbin/batctl meshif bat%02d tg' % (Segment)).split()
        GwName = None

        try:
            BatctlCmd = subprocess.run(BatctlTgCmd, stdout=subprocess.PIPE)
            BatTgResult = BatctlCmd.stdout.decode('utf-8')
        except:
            print('++ ERROR accessing batman TG:',BatctlCmd)
            BatTgResult = ''

        for BatLine in BatTgResult.split('\n'):
            BatTgInfo = BatLine.replace('(','').replace(')','').split()

            if len(BatTgInfo) > 6 and BatTgInfo[0] == '*' and BatTgInfo[2] == '-1':
                GwClientMAC  = BatTgInfo[1]

                if BatTgInfo[5] == badGwMAC and GwMacTemplate.match(GwClientMAC):      # e.g. "02:00:39:12:08:06"

                    if int(GwClientMAC[9:11]) == Segment:
                        GwName = 'gw'+GwClientMAC[12:14]+'n'+GwClientMAC[15:17]
                        print('   ... Gateway found by Batctl TG: %s = %s (%s)' % (badGwMAC, GwName, GwClientMAC))
                        break
                    else:
                        self.__alert('!! GW-Shortcut detected: bat%02d -> %s' % (Segment, GwClientMAC))

        return GwName



    #--------------------------------------------------------------------------
    # private function "__GetSegmentGwListFromBatman"
    #
    #    Returns List of Gateways in given Segment
    #
    #--------------------------------------------------------------------------
    def __GetSegmentGwListFromBatman(self, Segment):

        GwList    = []
        BatctlGwlCmd = ('/usr/sbin/batctl meshif bat%02d gwl' % (Segment)).split()

        try:
            BatctlCmd = subprocess.run(BatctlGwlCmd, stdout=subprocess.PIPE)
            BatResult = BatctlCmd.stdout.decode('utf-8')
        except:
            print('++ ERROR accessing batman GWL:',BatctlCmd)
            BatResult = ''

        for BatLine in BatResult.split('\n'):
            BatctlInfo = BatLine.split()

            if len(BatctlInfo) > 3:
                GwMAC  = BatctlInfo[0]
                GwName = None

                if GwMacTemplate.match(GwMAC):      # e.g. "02:00:35:12:08:06"
                    if int(GwMAC[9:11]) == Segment:
                        GwName = 'gw'+GwMAC[12:14]+'n'+GwMAC[15:17]
                    else:
                        self.__alert('!! GW-Shortcut detected: bat%02d -> %s' % (Segment, GwMAC))

                elif MacAdrTemplate.match(GwMAC):
                    print('++ Invalid Gateway MAC: bat%02d -> %s' % (Segment, GwMAC))
                    GwName = self.__GetGwMACfromBatmanTG(Segment, GwMAC)

                if GwName is not None:
                    if GwName not in GwList:
                        GwList.append(GwName)

        return GwList



    #==========================================================================
    # private init function "__GetGatewaysFromBatman"
    #
    #   Result = __GatewayDict[GwInstanceName] -> IPs and Segments for the GW
    #
    #--------------------------------------------------------------------------
    def __GetGatewaysFromBatman(self):

        print('\nChecking Batman for Gateways ...')

        for Segment in sorted(self.__SegmentDict):
            if len(self.__SegmentDict[Segment]['GwGitNames']) > 0:
                GwList = self.__GetSegmentGwListFromBatman(Segment)
            else:
                GwList = []

            for GwName in GwList:
                if GwName not in self.__GatewayDict:
                    self.__GatewayDict[GwName] = { 'IPs':[], 'DnsSegments':[], 'BatmanSegments':[] }
                    print('++ Inofficial Gateway found: %s' % (GwName))

                if Segment not in self.__GatewayDict[GwName]['BatmanSegments']:
                    self.__GatewayDict[GwName]['BatmanSegments'].append(Segment)
#                    print('++ Gateway in Batman but not in DNS:',Segment,GwName)

                if GwName not in self.__SegmentDict[Segment]['GwBatNames']:
                    self.__SegmentDict[Segment]['GwBatNames'].append(GwName)

            for GwName in self.__SegmentDict[Segment]['GwDnsNames']:
                if GwName not in self.__SegmentDict[Segment]['GwBatNames'] and Segment > 0 and Segment <= 64:
                    self.__alert('!! Gateway in DNS but not in Batman: Seg.%02d -> %s' % (Segment,GwName))

        print()
        for Segment in sorted(self.__SegmentDict):
            print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwBatNames'])))

        print()
        for GwName in sorted(self.__GatewayDict):
            print(GwName.ljust(7),'->',sorted(self.__GatewayDict[GwName]['BatmanSegments']))

        print('\n... done.\n')
        return



    #==============================================================================
    # public function "CheckGatewayDnsServer"
    #
    #
    #==============================================================================
    def CheckGatewayDnsServer(self):

        print('\nChecking DNS-Server on Gateways ...')

        DnsResolver = None

        try:
            DnsResolver = dns.resolver.Resolver()
            DnsResolver.timeout = 3
            DnsResolver.lifetime = 3
        except:
            DnsResolver = None

        if DnsResolver is not None:
            for Segment in sorted(self.__SegmentDict.keys()):
                if Segment in SegmentIgnoreList:  continue

                print('... Segment %02d' % (Segment))

                for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                    if GwName not in GwIgnoreList:
                        InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int((Segment-1)/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
#                        InternalGwIPv6 = 'fd21:b4dc:4b%02d::a38:%d' % ( Segment, int(GwName[2:4])*100 + int(GwName[6:8]) )

#                        for DnsServer in [InternalGwIPv4,InternalGwIPv6]:
                        for DnsServer in [InternalGwIPv4]:
                            DnsResolver.nameservers = [DnsServer]

#                            for DnsType in ['A','AAAA']:
                            for DnsType in ['A']:
                                DnsResult = None
                                Retries = len(InternetTestTargets)
                                TestIdx = 0

                                while DnsResult is None and TestIdx < Retries:
                                    try:
                                        DnsResult = DnsResolver.query(InternetTestTargets[TestIdx],DnsType)
                                    except:
                                        time.sleep(1)
                                        DnsResult = None
                                        TestIdx += 1
                                    else:
                                        Retries = 0
                                        if DnsResult is None:
                                            self.__alert('    !! No result on DNS-Server: Seg.%02d -> %s = %s -> %s' % (Segment,GwName,DnsServer,InternetTestTargets[TestIdx]) )

                                if DnsResult is None:
                                    self.__alert('    !! Error on DNS-Server: Seg.%02d -> %s = %s' % (Segment,GwName,DnsServer) )

        print('... done.\n')
        return



    #==============================================================================
    # public function "CheckGatewayDhcpServer"
    #
    #
    #==============================================================================
    def CheckGatewayDhcpServer(self):

        print('\nChecking DHCP-Server on Gateways ...')
        CheckDict = {}

        ffDhcpClient = DHCPClient()

        for Segment in sorted(self.__SegmentDict.keys()):
            if Segment in SegmentIgnoreList:  continue

            print('... Segment %02d' % (Segment))
            DhcpSegCount = 0

            for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                if GwName not in GwIgnoreList:
                    if GwName not in CheckDict:
                        CheckDict[GwName] = 0

                    InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int((Segment-1)/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )

                    DhcpResult = ffDhcpClient.CheckDhcp('bat%02d' % (Segment), InternalGwIPv4)

                    if DhcpResult is None:
#                        self.__alert('    !! Error on DHCP-Server: Seg.%02d -> %s' % (Segment,GwName))
                        print('    >> Error on DHCP-Server: Seg.%02d -> %s' % (Segment,GwName))
                        CheckDict[GwName] -= 8
                    else:
                        CheckDict[GwName] += 1
                        DhcpSegCount += 1

            if DhcpSegCount < 1:
                self.__alert('!!! No DHCP-Server available in Seg.%02d !' % (Segment))

        for GwName in CheckDict:
            if CheckDict[GwName] < 0:
                self.__alert('!!! Problem with DHCP-Server on %s !' % (GwName))

        print('... done.\n')
        return



    #==============================================================================
    # public function "CheckGatewayInternet"
    #
    #
    #==============================================================================
    def CheckGatewayInternet(self):

        print('\nChecking Internet-Connection via Gateways ...')

        PingCheckDict = {}
        HttpsCheckDict = {}
        DnsResolver = dns.resolver.Resolver()
        conf.verb = 0

        for Segment in sorted(self.__SegmentDict.keys()):
            if Segment in SegmentIgnoreList:  continue

            print('... Segment %02d' % (Segment))

            for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                if len(GwName) == 7 and GwName not in GwIgnoreList:
                    InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int((Segment-1)/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )

                    #---------- Ping ----------
                    PingResult = None
                    Retries = len(InternetTestTargets)
                    TestIdx = 0

                    if GwName not in PingCheckDict:
                        PingCheckDict[GwName] = 0

                    while PingResult is None and TestIdx < Retries:
                        TestIP = DnsResolver.query('%s.' % (InternetTestTargets[TestIdx]),'A')[0].to_text()
                        PingPacket = IP(dst=TestIP,ttl=20)/ICMP()
                        conf.route.resync()
                        conf.route.add(host=TestIP,gw=InternalGwIPv4)

                        try:
                            PingResult = sr1(PingPacket,timeout=1)
                        except:
                            time.sleep(1)
                            PingResult = None

                        if PingResult is None:
                            print('    >> Error on Ping to Internet: %s (%s) -> %s = %s' % (GwName,InternalGwIPv4,InternetTestTargets[TestIdx],TestIP))
                        elif PingResult.src != TestIP or PingResult.dst[:7] != InternalGwIPv4[:7]:
                            print('    >> Invalid response on Ping to Internet: %s (%s) -> %s = %s' % (GwName,InternalGwIPv4,InternetTestTargets[TestIdx],TestIP))
                       	    PingResult = None
#                        else:
#                            print('    Ping  ok: %s (%s) -> %s = %s' % (GwName,InternalGwIPv4,InternetTestTargets[TestIdx],TestIP))

                        TestIdx += 1

                    if PingResult is None:
                        PingCheckDict[GwName] -= 8
                    else:
                        PingCheckDict[GwName] += 1

                    #---------- HTTPS ----------
                    HttpsResult = None
                    Retries = len(InternetTestTargets)
                    TestIdx = 0

                    if GwName not in HttpsCheckDict:
                        HttpsCheckDict[GwName] = 0

                    while HttpsResult is None and TestIdx < Retries:
                        TestIP = DnsResolver.query('%s.' % (InternetTestTargets[TestIdx]),'A')[0].to_text()
                        TcpPacket = IP(dst=TestIP,ttl=64)/TCP(dport=443,sport=random.randrange(49152,65535))
                        conf.route.resync()
                        conf.route.add(host=TestIP,gw=InternalGwIPv4)

                        try:
                            HttpsResult = sr1(TcpPacket,timeout=2)
                        except:
                            time.sleep(1)
                            HttpsResult = None

                        if HttpsResult is None:
                            print('    >> No Response on HTTPS: %s (%s) -> %s = %s' % (GwName,InternalGwIPv4,InternetTestTargets[TestIdx],TestIP))
                        elif HttpsResult.src != TestIP or HttpsResult.dst[:7] != InternalGwIPv4[:7]:
                            print('    >> Invalid Response on HTTPS to Internet: %s (%s) -> %s = %s' % (GwName,InternalGwIPv4,InternetTestTargets[TestIdx],TestIP))
                            HttpsResult = None
#                        else:
#                            print('    HTTPS ok: %s (%s) -> %s = %s' % (GwName,InternalGwIPv4,InternetTestTargets[TestIdx],TestIP))

                        TestIdx += 1

                    if HttpsResult is None:
                        HttpsCheckDict[GwName] -= 8
                    else:
                        HttpsCheckDict[GwName] += 1

            for GwName in PingCheckDict:
                if PingCheckDict[GwName] < 0:
                    self.__alert('    !!! Error on Ping to Internet: Seg.%02d -> %s' % (Segment,GwName))

            for GwName in HttpsCheckDict:
                if HttpsCheckDict[GwName] < 0:
                    self.__alert('    !!! Error on HTTPS to Internet: Seg.%02d = %s' % (Segment,GwName))

        conf.route.resync()
        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__LoadNodeKeysFromGit"
    #
    #   Load and analyse fastd-Key of Nodes from Git
    #
    #     self.__FastdKeyDict[FastdKey] = { 'KeyDir','KeyFile','SegMode','PeerMAC','PeerName','VpnMAC','Timestamp','Dns4Seg','Dns6Seg' }
    #
    #-----------------------------------------------------------------------
    def __LoadNodeKeysFromGit(self):

        print('Load and analyse fastd-Key of Nodes from Git ...')

        KeyFileList = glob(os.path.join(self.__GitPath,'vpn*/peers/*'))

        for KeyFilePath in KeyFileList:
            PeerMAC  = None
            PeerName = ''
            PeerKey  = ''
            SegMode  = 'auto'
            SegDir   = os.path.dirname(KeyFilePath).split("/")[-2]
            Segment  = int(SegDir[3:])
            FileName = os.path.basename(KeyFilePath)

            if PeerTemplate.match(FileName):
                PeerID = FileName.lower()
            else:
                PeerID = None

            if (Segment == 0) or (Segment > 64):
                print('!! Illegal Segment: %0d' % (Segment))
                continue

            if Segment not in self.__SegmentDict:
                print('!! Segment without Gateway: %0d' % (Segment))

                self.__SegmentDict[Segment] = {
                    'GwGitNames':[],
                    'GwDnsNames':[],
                    'GwBatNames':[],
                    'GwIPs':[]
                }

            with open(KeyFilePath,'r') as KeyFile:
                KeyData  = KeyFile.read()

            for DataLine in KeyData.split('\n'):
                LowerCharLine = DataLine.lower().strip()

                if LowerCharLine.startswith('#mac: '):
                    PeerMAC = LowerCharLine[6:]
                elif LowerCharLine.startswith('#hostname: '):
                    PeerName = DataLine[11:]
                elif LowerCharLine.startswith('#segment: '):
                    SegMode = LowerCharLine[10:]
                elif LowerCharLine.startswith('key '):
                    PeerKey = LowerCharLine.split('"')[1]
                elif not LowerCharLine.startswith('#') and LowerCharLine != '':
                    self.__alert('!! Invalid Entry in Key File: %s -> %s' % (KeyFilePath,DataLine))

            if PeerMAC is not None:
                if not MacAdrTemplate.match(PeerMAC):
                    self.__alert('!! Invalid MAC in Key File: %s -> %s' % (KeyFilePath,PeerMAC))
                    PeerMAC = None

            if PeerID is not None:
                if PeerMAC is None:
                    PeerMAC = '%s:%s:%s:%s:%s:%s' % (PeerID[4:6],PeerID[6:8],PeerID[8:10],PeerID[10:12],PeerID[12:14],PeerID[14:16])
                    self.__alert('!! Peer MAC set by KeyFileName: %s -> %s' % (KeyFilePath,PeerMAC))
                elif PeerMAC.replace(':','') != PeerID[4:]:
                    self.__alert('!! Key Filename does not match MAC: %s -> %s' % (KeyFilePath,PeerMAC))

            if not FastdKeyTemplate.match(PeerKey):
                self.__alert('!! Invalid Key in Key File: %s -> %s' % (KeyFilePath,PeerKey))
                PeerKey = None


            if PeerMAC is None or PeerKey is None:
                print('>> Invalid Key File: %s' % (KeyFilePath))
            else:
                if PeerKey in self.__FastdKeyDict:
                    self.__alert('!! Duplicate Key: %s -> %s / %s = %s' % (PeerKey,SegDir,FileName,PeerName))
                    self.__alert('                        %s/peers/%s = %s' % (self.__FastdKeyDict[PeerKey]['KeyDir'],self.__FastdKeyDict[PeerKey]['KeyFile'],self.__FastdKeyDict[PeerKey]['PeerName']))
                    self.AnalyseOnly = True
                elif GwMacTemplate.match(PeerMAC):
                    print('!! GW Key in Peer Key File: %s -> %s' % (KeyFilePath,PeerMAC))
                else:
                    self.__FastdKeyDict[PeerKey] = {
                        'KeyDir'   : SegDir,
                        'KeyFile'  : FileName,
                        'SegMode'  : SegMode,
                        'PeerMAC'  : PeerMAC,
                        'PeerName' : PeerName,
                        'PeerSeg'  : int(SegDir[3:]),
                        'VpnMAC'   : None,
                        'VpnGW'    : None,
                        'Timestamp': 0,
                        'DnsName'  : 'ffs-%s-%s' % (PeerMAC.replace(':',''),PeerKey[:12]),
                        'Dns4Seg'  : None,
                        'Dns6Seg'  : None
                    }

        print('... done: %d\n' % (len(self.__FastdKeyDict)))
        return



    #-----------------------------------------------------------------------
    # private function "__AnalyseFastdStatus"
    #
    #   Analyse fastd-status.json
    #
    # FastdKey -> { URL, KeyFile, MAC }
    #
    #-----------------------------------------------------------------------
    def __AnalyseFastdStatus(self, FastdPeersDict, GwName, Segment, HttpTime):

        ActiveKeyCount = 0

        for PeerKey in FastdPeersDict:
            if FastdPeersDict[PeerKey]['connection'] is not None:

                if PeerKey in self.__FastdKeyDict:
                    for PeerVpnMAC in FastdPeersDict[PeerKey]['connection']['mac_addresses']:
                        if MacAdrTemplate.match(PeerVpnMAC) and not GwMacTemplate.match(PeerVpnMAC):
                            ActiveKeyCount += 1
                            self.__FastdKeyDict[PeerKey]['VpnMAC'] = PeerVpnMAC
                            self.__FastdKeyDict[PeerKey]['VpnGW']  = GwName
                            self.__FastdKeyDict[PeerKey]['Timestamp'] = HttpTime

                else:
                    print('!! PeerKey not in Git: %s = %s\n' % (FastdPeersDict[PeerKey]['name'],PeerKey))

        return ActiveKeyCount



    #-----------------------------------------------------------------------
    # private function "__LoadFastdStatusFile"
    #
    #   Load and analyse fastd-status.json
    #   (Key File Name from Git + MAC of Mesh-VPN)
    #
    # FastdKey -> { URL, KeyFile, MAC }
    #
    #-----------------------------------------------------------------------
    def __LoadFastdStatusFile(self, GwName, URL, Segment):

        ActiveConnections = 0
        jsonFastdDict = None
        Retries = 5

        while jsonFastdDict is None and Retries > 0:
            Retries -= 1

            try:
                FastdJsonHTTP = urllib.request.urlopen(URL,timeout=1)
                HttpTime = int(calendar.timegm(time.strptime(FastdJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = int(time.time()) - HttpTime
                jsonFastdDict = json.loads(FastdJsonHTTP.read().decode('utf-8'))
                FastdJsonHTTP.close()
            except:
#                print('** need retry ...')
                jsonFastdDict = None
                time.sleep(2)

        if jsonFastdDict is None:
            print('++ ERROR fastd status connect! %s' % (URL))
            return None

        if StatusAge < MaxStatusAge:
            if 'peers' in jsonFastdDict:
                if 'interface' in jsonFastdDict:
                    if int(jsonFastdDict['interface'][3:5]) != Segment:
                        print('!! Bad Interface in fastd status file: %s = %s -> %02d' % (URL,jsonFastdDict['interface'],Segment))
                        return None

                ActiveConnections = self.__AnalyseFastdStatus(jsonFastdDict['peers'],GwName,Segment,HttpTime)
            else:
                print('!! Bad fastd status file! %s' % (URL))
        else:
            print('++ fastd status to old! %s' % (URL))

        return ActiveConnections



    #-----------------------------------------------------------------------
    # private function "__GetFastdStatusFileList"
    #
    #   Get List of fastd-status.json files on Gateway
    #
    #-----------------------------------------------------------------------
    def __GetFastdStatusFileList(self, URL, ffSeg):

        FileList = None
        Retries  = 5

        while Retries > 0:
            Retries -= 1

            try:
                FastdHTTPlist = urllib.request.urlopen(URL,timeout=1)
                HttpData = FastdHTTPlist.read().decode('utf-8')
                FastdHTTPlist.close()
            except:
                print('** need retry ...')
                HttpData = None
                time.sleep(2)
            else:
                Retries = 0

        if HttpData is not None:
            FileList = []
            InfoBlock = HttpData.split('\"')

            for info in InfoBlock:
                if FastdFileTemplate.match(info):
                    if int(info[3:5]) == ffSeg:
                        FileList.append(info)

        return FileList



    #--------------------------------------------------------------------------
    # private function "__LoadFastdStatusInfos"
    #
    #   Load and analyse fastd-status.json
    #   (Key File Name from Git + MAC of Mesh-VPN)
    #
    # FastdKey -> { URL, KeyFile, MAC }
    #
    #--------------------------------------------------------------------------
    def __LoadFastdStatusInfos(self):

        print('-------------------------------------------------------')
        print('Loading fastd Status Infos ...\n')
        TotalUplinks = 0

        for GwName in sorted(self.__GatewayDict):
            if GwName in GwIgnoreList or GwName in ['gw04n05']:
                print('... %s ... ignored.\n' % (GwName))
            elif len(self.__GatewayDict[GwName]['BatmanSegments']) > 0:
                ConnectionCount = 0

                for ffSeg in sorted(self.__GatewayDict[GwName]['BatmanSegments']):
                    GwDataURL = 'http://10.%d.%d.%d/data/' % ( 190+int((ffSeg-1)/32), ((ffSeg-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
                    FileList = self.__GetFastdStatusFileList(GwDataURL,ffSeg)

                    if FileList is None:
                        print('... %s / Seg.%02d -> ERROR' % (GwName,ffSeg))
                    elif len(FileList) < 1:
                        print('... %s / Seg.%02d -> Missing File!' % (GwName,ffSeg))
                    else:
                        for JsonFile in FileList:
                            ActiveConnections = self.__LoadFastdStatusFile(GwName,GwDataURL+JsonFile,ffSeg)

                            if ActiveConnections is not None and ActiveConnections != 0:
                                print('... %s / %s = %d' % (GwName,JsonFile,ActiveConnections))
                                ConnectionCount += ActiveConnections

                if ConnectionCount > 0:
                    print('    >>>>>>> VPN-Connections: %d\n' % (ConnectionCount))
                    TotalUplinks += ConnectionCount
                else:
                    print('... %s ... no VPN-Connections.\n' % (GwName))

        print('... done: %d' % (TotalUplinks))
        print('-------------------------------------------------------')
        return



    #--------------------------------------------------------------------------
    # private function "__CheckNodesInSegassignDNS"
    #
    #--------------------------------------------------------------------------
    def __CheckNodesInSegassignDNS(self):

        SegAssignDomain = self.__DnsAccDicts[0]['SegAssignDomain']

        SegAssignDnsServer = ffDnsServer(SegAssignDomain, self.__DnsAccDicts[0])
        dicSegAssignZone = SegAssignDnsServer.GetDnsZone()

        if dicSegAssignZone is None:
            self.__alert('!! ERROR: DNS Zone not available !!')
            self.AnalyseOnly = True
            return

        if SegAssignDnsServer.ReadOnly:
            self.__alert('!! ERROR: DNS cannot be updated if neccessary !!')
            self.AnalyseOnly = True

        #---------- Check DNS against Git ----------
        print('Checking SegAssign DNS Entries against KeyFiles in Git ...')
        for PeerDnsName in dicSegAssignZone:
            if DnsNodeTemplate.match(PeerDnsName):
                if PeerDnsName in self.__PeerDnsDict:
                    FastdKey = self.__PeerDnsDict[PeerDnsName]
                    GitSegment = self.__FastdKeyDict[FastdKey]['PeerSeg']

                    for PeerIP in dicSegAssignZone[PeerDnsName]:
                        if DnsIP6SegTemplate.match(PeerIP):
                            #---------- IPv6 ----------
                            DnsSegment = int(PeerIP.split(':')[-1].zfill(1))

                            if DnsSegment == GitSegment:
                                self.__FastdKeyDict[FastdKey]['Dns6Seg'] = DnsSegment
                            else:
                                self.__alert('++ Segment mismatch for NodeID %s: DNSv6 = %d / Git = %d' % (PeerDnsName, DnsSegment, GitSegment))
                                SegAssignDnsServer.DelEntry(PeerDnsName, PeerIP)

                        elif DnsIP4SegTemplate.match(PeerIP):
                            #---------- IPv4 ----------
                            DnsSegment = int(PeerIP.split('.')[-1])

                            if DnsSegment == GitSegment:
                                self.__FastdKeyDict[FastdKey]['Dns4Seg'] = DnsSegment
                            else:
                                self.__alert('++ Segment mismatch for NodeID %s: DNSv4 = %d / Git = %d' % (PeerDnsName, DnsSegment, GitSegment))
                                SegAssignDnsServer.DelEntry(PeerDnsName, PeerIP)

                        else:  # invalid IP-Address for SegAssign
                            self.__alert('++ Invalid IP-Entry for NodeID %s: %s' % (PeerDnsName, PeerIP))
                            SegAssignDnsServer.DelEntry(PeerDnsName, PeerIP)

                else:
                    self.__alert('++ Unknown DNS Node-Entry will be deleted: %s' % (PeerDnsName))
                    SegAssignDnsServer.DelEntry(PeerDnsName, None)

            elif PeerDnsName != '@' and PeerDnsName != '*':
                self.__alert('!! Invalid DNS Entry: %s' % (PeerDnsName))
#                SegAssignDnsServer.DelEntry(PeerDnsName, None)


        #---------- Check Git for missing DNS entries ----------
        print('Checking KeyFiles from Git for missing DNS Entries ...')

        for PeerKey in self.__FastdKeyDict:
            PeerDnsName = self.__FastdKeyDict[PeerKey]['DnsName']
            GitSegment = int(self.__FastdKeyDict[PeerKey]['KeyDir'][3:])

            if self.__FastdKeyDict[PeerKey]['Dns6Seg'] is None:
                self.__alert('!! DNSv6 Entry missing: %s -> %s = %s' % (self.__FastdKeyDict[PeerKey]['KeyFile'], self.__FastdKeyDict[PeerKey]['PeerMAC'], self.__FastdKeyDict[PeerKey]['PeerName']))
                PeerDnsIPv6 = '%s%d' % (SegAssignIPv6Prefix, GitSegment)
                SegAssignDnsServer.AddEntry(PeerDnsName, PeerDnsIPv6)
                self.__FastdKeyDict[PeerKey]['Dns6Seg'] = GitSegment

            if self.__FastdKeyDict[PeerKey]['Dns4Seg'] is None:
                self.__alert('!! DNSv4 Entry missing: %s -> %s = %s' % (self.__FastdKeyDict[PeerKey]['KeyFile'], self.__FastdKeyDict[PeerKey]['PeerMAC'], self.__FastdKeyDict[PeerKey]['PeerName']))
                PeerDnsIPv4 = '%s%d' % (SegAssignIPv4Prefix, GitSegment)
                SegAssignDnsServer.AddEntry(PeerDnsName, PeerDnsIPv4)
                self.__FastdKeyDict[PeerKey]['Dns4Seg'] = GitSegment


        if not SegAssignDnsServer.CommitChanges():
            self.__alert('!! ERROR on updating DNS Zone \"%s\" !!' % (SegAssignDomain))

        return


    #--------------------------------------------------------------------------
    # private function "__SetupPeerDnsDict"
    #
    #--------------------------------------------------------------------------
    def __SetupPeerDnsDict(self):

        for PeerKey in self.__FastdKeyDict:
       	    PeerDnsName = self.__FastdKeyDict[PeerKey]['DnsName']

            if PeerDnsName in self.__PeerDnsDict:
                self.__alert('!! Duplicate DNS-ID: %s' % (PeerDnsName))
                self.AnalyseOnly = True

            self.__PeerDnsDict[PeerDnsName] = PeerKey

        return



    #=========================================================================
    # public function "GetNodeUplinkInfos"
    #
    #   Returns Dictionary with fastd-Infos
    #
    #=========================================================================
    def GetNodeUplinkInfos(self):

        self.__LoadNodeKeysFromGit()
        self.__LoadFastdStatusInfos()
        self.__SetupPeerDnsDict()
        self.__CheckNodesInSegassignDNS()

        return self.__FastdKeyDict



    #=========================================================================
    # public function "GetSegmentList"
    #
    #   Returns List of Segments
    #
    #=========================================================================
    def GetSegmentList(self):

        SegmentList = []

        for Segment in self.__SegmentDict.keys():
            if len(self.__SegmentDict[Segment]['GwBatNames']) > 0:
                SegmentList.append(Segment)

        return SegmentList



    #==============================================================================
    # public function "MoveNodes"
    #
    #   Moving Nodes in GIT and DNS
    #==============================================================================
    def MoveNodes(self, NodeMoveDict, GitAccount):

        print('Moving Nodes in GIT and DNS ...')

        if len(NodeMoveDict) < 1:
#        if True:
            print(NodeMoveDict)
            print('++ There are no Peers to be moved.')
            return

        if  self.__GitPath is None or GitAccount is None:
            print('!! Git Account Data is not available!')
            return

        SegAssignDomain = self.__DnsAccDicts[0]['SegAssignDomain']
        SegAssignDnsServer = ffDnsServer(SegAssignDomain, self.__DnsAccDicts[0])

        if SegAssignDnsServer.ReadOnly:
            self.__alert('!! ERROR: DNS cannot be updated !!')
            self.AnalyseOnly = True

        if self.AnalyseOnly:
            print('++ Nodes cannot be moved due to AnalyseOnly-Mode.')
            return

#        exit(1)

        try:
            GitLockName = os.path.join('/tmp','.'+os.path.basename(self.__GitPath)+'.lock')
            LockFile = open(GitLockName, mode='w+')
            fcntl.lockf(LockFile, fcntl.LOCK_EX)

            GitRepo   = git.Repo(self.__GitPath)
            GitIndex  = GitRepo.index
            GitOrigin = GitRepo.remotes.origin

            if GitRepo.is_dirty() or len(GitRepo.untracked_files) > 0:
                self.__alert('!! The Git Repository ist clean - cannot move Nodes!')
            else:
                self.__alert('++ The following Nodes will be moved automatically:')
                GitCommitMessage = "Automatic move by FFS-Monitor:\n\n"
                MoveCount = 0

                for FastdKey in NodeMoveDict:
                    KeyFileName = self.__FastdKeyDict[FastdKey]['KeyFile']
                    DestSegment = NodeMoveDict[FastdKey]

                    if DestSegment > 0 and DestSegment < 99:
                        SourceFile = '%s/peers/%s' % (self.__FastdKeyDict[FastdKey]['KeyDir'], KeyFileName)
                        DestFile   = 'vpn%02d/peers/%s' % (DestSegment, KeyFileName)
                        PeerDnsName = self.__FastdKeyDict[FastdKey]['DnsName']

#                        print(SourceFile,'->',DestFile)
                        MoveTextLine = '%s = \"%s\": %s -> vpn%02d' % (KeyFileName, self.__FastdKeyDict[FastdKey]['PeerName'], self.__FastdKeyDict[FastdKey]['KeyDir'], DestSegment)
                        print(MoveTextLine)

                        if os.path.exists(os.path.join(self.__GitPath,SourceFile)):
                            MoveCount += 1
                            GitCommitMessage += MoveTextLine+'\n'
                            GitIndex.remove([os.path.join(self.__GitPath, SourceFile)])
                            print('... Git remove of old location done.')

                            os.rename(os.path.join(self.__GitPath, SourceFile), os.path.join(self.__GitPath, DestFile))
                            print('... File moved.')
                            GitIndex.add([os.path.join(self.__GitPath, DestFile)])
                            print('... Git add of new location done.')
                            SegAssignDnsServer.ReplaceEntry(PeerDnsName, '%s%d' % (SegAssignIPv6Prefix, DestSegment))
                            SegAssignDnsServer.ReplaceEntry(PeerDnsName, '%s%d' % (SegAssignIPv4Prefix, DestSegment))

#                            self.__alert('   '+SourceFile+' -> '+DestFile)
                            self.__alert('   %s = %s: %s -> vpn%02d' % (KeyFileName, self.__FastdKeyDict[FastdKey]['PeerName'], self.__FastdKeyDict[FastdKey]['KeyDir'], DestSegment))

                        else:
                            print('... Key File was already moved by other process.')

                    else:
                        self.__alert('!! Invalid NodeMove Entry: %s / %s = %s -> vpn%02d' % (self.__FastdKeyDict[FastdKey]['KeyDir'],KeyFileName,self.__FastdKeyDict[FastdKey]['PeerName'],DestSegment))


                if MoveCount > 0:
                    print('... doing Git commit ...')
                    GitIndex.commit(GitCommitMessage)
                    GitOrigin.config_writer.set('url',GitAccount['URL'])
                    print('... doing Git pull ...')
                    GitOrigin.pull()
                    print('... doing Git push ...')
                    GitOrigin.push()

                    if not SegAssignDnsServer.CommitChanges():
                        self.__alert('!! ERROR on updating DNS Zone \"%s\" !!' % (SegAssignDomain))
                else:
                    self.__alert('>>> No valid movements available!')

        except:
            self.__alert('!! Fatal ERROR on moving Node(s)!')

        finally:
            del GitOrigin
            del GitIndex
            del GitRepo

            fcntl.lockf(LockFile,fcntl.LOCK_UN)
            LockFile.close()

        print('... done.\n')
        return
