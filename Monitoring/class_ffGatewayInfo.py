#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  class_ffGatewayInfo.py                                                                 #
#                                                                                         #
#  Analyse fastd-Keys from Git and fastd-Status-Info from Gateways.                       #
#                                                                                         #
#                                                                                         #
#  Needed json-Files:                                                                     #
#                                                                                         #
#       fastd/vpn??.json     -> fastd-Keys (live Data) from Gateways                      #
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
import socket
import urllib.request
import time
import datetime
import calendar
import json
import re
import fcntl
import git

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



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

DNS_RETRIES         = 3
DHCP_RETRIES        = 5
PING_RETRIES        = 3
HTTPS_RETRIES       = 3

MaxStatusAge        = 15 * 60        # 15 Minutes (in Seconds)
MinGatewayCount     = 1              # minimum number of Gateways per Segment

FreifunkGwDomain    = 'gw.freifunk-stuttgart.de'

SegAssignDomain     = 'segassign.freifunk-stuttgart.de'
SegAssignIPv6Prefix = '2001:2:0:711::'

GwIgnoreList        = ['gw04n03','gw04n05','gw05n01','gw05n08','gw05n09']

InternetTestTarget  = 'www.google.de'

DnsSegTemplate      = re.compile('^'+SegAssignIPv6Prefix+'(([0-9a-f]{1,4}:){1,2})?[0-9]{1,2}$')
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
    def __init__(self,GitPath,DnsAccDict):

        # public Attributes
        self.Alerts       = []           # List of  Alert-Messages
        self.AnalyseOnly  = False        # Blocking active Actions due to inconsistent Data

        # private Attributes
        self.__GitPath     = GitPath
        self.__DnsAccDict  = DnsAccDict  # DNS Account
        self.__DnsServerIP = None

        self.__GatewayDict = {}          # GatewayDict[GwInstanceName] -> IPs, DnsSegments, BatmanSegments
        self.__SegmentDict = {}          # SegmentDict[SegmentNumber]  -> GwGitNames, GwDnsNames, GwBatNames, GwIPs
        self.__GwAliasDict = {}          # GwAliasDict[LegacyName]     -> current new Gateway
        self.__Key2FileNameDict = {}     # Key2FileNameDict[PeerKey]   -> SegDir, KeyFileName
        self.__FastdKeyDict = {}         # FastdKeyDic[KeyFileName]    -> SegDir, VpnMAC, PeerMAC, PeerName, PeerKey

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
    def __alert(self,Message):

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



    #--------------------------------------------------------------------------
    # private function "__GetIpFromCNAME"
    #
    #    Returns True if everything is OK
    #
    #--------------------------------------------------------------------------
    def __GetIpFromCNAME(self,DnsName):

        DnsResolver = None
        IpList = []

        try:
            DnsResolver = dns.resolver.Resolver()
        except:
            DnsResolver = None

        if DnsResolver is not None:
            for DnsType in ['A','AAAA']:
                try:
                    DnsResult = DnsResolver.query(DnsName,DnsType)
                except:
                    DnsResult = None

                if DnsResult is not None:
                    for GatewayIP in DnsResult:
#                        print('>>> GwIP:',GatewayIP)  #................................................
                        IpList.append(GatewayIP.to_text())

            try:
                DnsResult = DnsResolver.query(DnsName,'CNAME')
            except:
                DnsResult = None

            if DnsResult is not None:
                for Cname in DnsResult:
                    GwName = Cname.to_text()
                    print('>>> GwName/Cname: %s' % (GwName))  #................................................
                    IpList.append(self.__GetIpFromCNAME(GwName))

        return IpList



    #--------------------------------------------------------------------------
    # private function "__GetGwInstances"
    #
    #
    #--------------------------------------------------------------------------
    def __GetGwInstances(self,GwName,DnsDomain,DnsResult):

        for rds in DnsResult:
            if rds.rdtype == dns.rdatatype.A or rds.rdtype == dns.rdatatype.AAAA:
                for IpRecord in rds:
                    IpAddress = IpRecord.to_text()

                    if IpAddress not in self.__GatewayDict[GwName]['IPs']:
                        self.__GatewayDict[GwName]['IPs'].append(IpAddress)

            elif rds.rdtype == dns.rdatatype.CNAME:
                for CnRecord in rds:
                    Cname = CnRecord.to_text()

                    if Cname[-1] != '.':
                        Cname += '.' + DnsDomain

                    IpList = self.__GetIpFromCNAME(Cname)

                    for IpAddress in IpList:
                        if IpAddress not in self.__GatewayDict[GwName]['IPs']:
                            self.__GatewayDict[GwName]['IPs'].append(IpAddress)

        return



    #--------------------------------------------------------------------------
    # private function "__GetSegmentGwIPs"
    #
    #    Returns List of IPs
    #
    #--------------------------------------------------------------------------
    def __GetSegmentGwIPs(self,DnsDomain,DnsResult):

        IpList = []

        for rds in DnsResult:
            if rds.rdtype == dns.rdatatype.A or rds.rdtype == dns.rdatatype.AAAA:
                for IpRecord in rds:
                    IpAddress = IpRecord.to_text()

                    if IpAddress not in IpList:
                        IpList.append(IpAddress)

            elif rds.rdtype == dns.rdatatype.CNAME:
                for CnRecord in rds:
                    Cname = CnRecord.to_text()

                    if Cname[-1] != '.':
                        Cname += '.' + DnsDomain

                    CnameIpList = self.__GetIpFromCNAME(Cname)

                    for IpAddress in CnameIpList:
                        if IpAddress not in IpList:
                            IpList.append(IpAddress)

        return IpList



    #--------------------------------------------------------------------------
    # private function "__GetDnsZone"
    #
    #    Returns List of IPs
    #
    #--------------------------------------------------------------------------
    def __GetDnsZone(self,DnsDomain):

        DnsZone = None

        try:
            DnsResolver = dns.resolver.Resolver()
            DnsServerIP = DnsResolver.query('%s.' % (self.__DnsAccDict['Server']),'A')[0].to_text()
            DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,DnsDomain))
        except:
            self.__alert('!! ERROR on fetching DNS Zone from Primary: %s' % (DnsDomain))
            DnsZone = None
            self.AnalyseOnly = True

        if DnsZone is None:
            try:
                DnsServerIP = DnsResolver.query('%s.' % (self.__DnsAccDict['Server2']),'A')[0].to_text()
                DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,DnsDomain))
            except:
                self.__alert('!! ERROR on fetching DNS Zone from Secondary: %s' % (DnsDomain))
                DnsZone = None

        return DnsZone



    #==========================================================================
    # private init function "__GetGatewaysFromDNS"
    #
    #   Result = __GatewayDict[GwInstanceName] -> IPs and Segments for the GW
    #
    #--------------------------------------------------------------------------
    def __GetGatewaysFromDNS(self):

        print('Checking DNS for Gateway Instances: %s ...' % (FreifunkGwDomain))

        Ip2GwDict = {}
        DnsZone   = self.__GetDnsZone(FreifunkGwDomain)

        if DnsZone is None:
            print('++ DNS Zone is empty: %s' % (FreifunkGwDomain))

        else:
            #----- get Gateways from Zone File -----
            for name, node in DnsZone.nodes.items():
                GwName = name.to_text()

                if GwInstanceTemplate.match(GwName):
                    if GwName not in self.__GatewayDict:
                        self.__GatewayDict[GwName] = { 'IPs':[], 'DnsSegments':[], 'BatmanSegments':[] }

                    self.__GetGwInstances(GwName,FreifunkGwDomain,node.rdatasets)

                if GwSegGroupTemplate.match(GwName):
                    if len(GwName) == 7:
                        Segment = int(GwName[5:])
                    else:
                        Segment = 99    # legacy names are used for onboarding

                    if Segment == 0 or Segment > 64:
                        continue    # >>> Onboarder or Quarantine

                    if Segment not in self.__SegmentDict:
                        print('!! Segment in DNS but not in Git: %s' % (GwName))

                        self.__SegmentDict[Segment] = {
                            'GwGitNames':[],
                            'GwDnsNames':[],
                            'GwBatNames':[],
                            'GwIPs':[]
                        }

                    self.__SegmentDict[Segment]['GwIPs'] += self.__GetSegmentGwIPs(FreifunkGwDomain,node.rdatasets)

            #----- setting up GwIP to GwInstanceName -----
            for GwName in self.__GatewayDict:
                for GwIP in self.__GatewayDict[GwName]['IPs']:
                    if GwIP not in Ip2GwDict:
                        Ip2GwDict[GwIP] = GwName
                    else:
                        if Ip2GwDict[GwIP][:4] == GwName[:4] and len(GwName) != len(Ip2GwDict[GwIP]):
                            print('++ Gateway Alias: %s = %s = %s' % (GwIP,GwName,Ip2GwDict[GwIP]))

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
                    print('%-15s -> %s' % (GwIP,Ip2GwDict[GwIP]))

            print()
            for GwIP in sorted(Ip2GwDict):
                if ':' in GwIP:
                    print('%-36s -> %s' % (GwIP,Ip2GwDict[GwIP]))

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
                                self.__alert('!! DNS entries are inconsistent: %s -> %02d' % (GwName,Segment))
                    else:
                        self.__alert('!! Unknown Gateway IP: %s' % (GwIP))

                if len(self.__SegmentDict[Segment]['GwGitNames']) > 0:
                    if len(self.__SegmentDict[Segment]['GwDnsNames']) < MinGatewayCount:
                        self.__alert('!! Too few Gateways in Segment %02d: %s' % (Segment,self.__SegmentDict[Segment]['GwDnsNames']))
                    else:
                        print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwDnsNames'])))
                else:
                    self.__alert('!! Gateway in DNS but not in Git for Segment %02d: %s' % (Segment,self.__SegmentDict[Segment]['GwDnsNames']))

            print()
            for GwName in sorted(self.__GatewayDict):
                print(GwName.ljust(7),'->',sorted(self.__GatewayDict[GwName]['DnsSegments']))

        print('\n... done.\n')
        return



    #--------------------------------------------------------------------------
    # private function "__GetSegmentGwListFromBatman"
    #
    #    Returns List of Gateways in given Segment
    #
    #--------------------------------------------------------------------------
    def __GetSegmentGwListFromBatman(self,Segment):

        BatResult = None
        GwList    = []

        BatctlCmd = ('/usr/sbin/batctl -m bat%02d gwl' % (Segment)).split()

        try:
            BatctlGwl = subprocess.run(BatctlCmd, stdout=subprocess.PIPE)
            BatResult = BatctlGwl.stdout.decode('utf-8')
        except:
            print('++ ERROR accessing batman:',BatctlCmd)
            BatResult = None
        else:
            for BatLine in BatResult.split('\n'):
                BatctlInfo = BatLine.split()

                if len(BatctlInfo) > 3:
                    GwMAC  = BatctlInfo[0]
                    GwName = None

                    if GwMacTemplate.match(GwMAC):      # e.g. "02:00:38:12:08:06"
                        if int(GwMAC[9:11]) == Segment:
                            GwName = 'gw'+GwMAC[12:14]+'n'+GwMAC[15:17]
                        else:
                            self.__alert('!! GW-Shortcut detected: bat%02d -> %s' % (Segment,GwMAC))

                    elif MacAdrTemplate.match(GwMAC):
                        print('++ Invalid Gateway MAC: bat%02d -> %s' % (Segment,GwMAC))

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
                print('... Segment %02d' % (Segment))

                for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                    if len(GwName) == 7 and GwName not in GwIgnoreList:
                        InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int((Segment-1)/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
#                        InternalGwIPv6 = 'fd21:b4dc:4b%02d::a38:%d' % ( Segment, int(GwName[2:4])*100 + int(GwName[6:8]) )

#                        for DnsServer in [InternalGwIPv4,InternalGwIPv6]:
                        for DnsServer in [InternalGwIPv4]:
                            DnsResolver.nameservers = [DnsServer]

#                            for DnsType in ['A','AAAA']:
                            for DnsType in ['A']:
                                DnsResult = None
                                Retries = DNS_RETRIES

                                while DnsResult is None and Retries > 0:
                                    Retries -= 1
                                    try:
                                        DnsResult = DnsResolver.query(InternetTestTarget,DnsType)
                                    except:
                                        time.sleep(1)
                                        DnsResult = None

                                if DnsResult is None:
                                    self.__alert('!! Error on DNS-Server: Seg.%02d -> %s = %s -> %s (%s)' % (Segment,GwName,DnsServer,InternetTestTarget,DnsType) )

        print('... done.\n')
        return



    #==============================================================================
    # public function "CheckGatewayDhcpServer"
    #
    #
    #==============================================================================
    def CheckGatewayDhcpServer(self):

        print('\nChecking DHCP-Server on Gateways ...')

        ffDhcpClient = DHCPClient()

        for Segment in sorted(self.__SegmentDict.keys()):
            print('... Segment %02d' % (Segment))

            for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                if len(GwName) == 7 and GwName not in GwIgnoreList:
                    InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int((Segment-1)/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
                    DhcpResult = None
                    Retries = DHCP_RETRIES

                    while DhcpResult is None and Retries > 0:
                        Retries -= 1
                        try:
                            DhcpResult = ffDhcpClient.CheckDhcp('bat%02d' % (Segment), InternalGwIPv4)
                        except:
                            time.sleep(1)
                            DhcpResult = None

                    if DhcpResult is None:
                        self.__alert('!! Error on DHCP-Server: Seg.%02d -> %s' % (Segment,GwName))

        print('... done.\n')
        return



    #==============================================================================
    # public function "CheckGatewayInternet"
    #
    #
    #==============================================================================
    def CheckGatewayInternet(self):

        print('\nChecking Internet-Connection via Gateways ...')

        DnsResolver = dns.resolver.Resolver()
        TestIP = DnsResolver.query('%s.' % (InternetTestTarget),'A')[0].to_text()
        PingPacket = IP(dst=TestIP,ttl=20)/ICMP()
        TcpPacket  = IP(dst=TestIP)/TCP(dport=[443])

        for Segment in sorted(self.__SegmentDict.keys()):
            print('... Segment %02d' % (Segment))

            for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                if len(GwName) == 7 and GwName not in GwIgnoreList:
                    InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int((Segment-1)/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
                    conf.verb = 0
                    conf.route.resync()
                    conf.route.add(host=TestIP,gw=InternalGwIPv4)

                    #---------- Ping ----------
                    PingResult = None
                    Retries = PING_RETRIES

                    while PingResult is None and Retries > 0:
                        Retries -= 1
                        try:
                            PingResult = sr1(PingPacket,timeout=2)
                        except:
                            time.sleep(1)
                            PingResult = None

                        if PingResult is not None:
                            if PingResult.src != TestIP or PingResult.dst[:7] != InternalGwIPv4[:7]:
                            	PingResult = None

                    if PingResult is None:
                        self.__alert('!! Error on Ping to Internet: Seg.%02d -> %s' % (Segment,GwName))


                    #---------- HTTPS ----------
                    HttpsResult = None
                    Retries = HTTPS_RETRIES

                    while HttpsResult is None and Retries > 0:
                        Retries -= 1
                        try:
                            HttpsResult = sr1(TcpPacket,inter=0.5,retry=-2,timeout=1)
                        except:
                            time.sleep(1)
                            HttpsResult = None

                        if HttpsResult is not None:
                            if HttpsResult.src != TestIP or HttpsResult.dst[:7] != InternalGwIPv4[:7]:
                                HttpsResult = None

                    if HttpsResult is None:
                        self.__alert('!! Error on HTTPS to Internet: Seg.%02d -> %s' % (Segment,GwName))

        conf.route.resync()
        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__LoadNodeKeysFromGit"
    #
    #   Load and analyse fastd-Key of Nodes from Git
    #
    #     self.__FastdKeyDict[KeyFileName] = { 'KeyDir','SegMode','PeerMAC','PeerName','PeerKey','VpnMAC','Timestamp','DnsSeg' }
    #     self.__Key2FileNameDict[PeerKey] = { 'KeyDir','KeyFile' }
    #
    #-----------------------------------------------------------------------
    def __LoadNodeKeysFromGit(self):

        print('Load and analyse fastd-Key of Nodes from Git ...')

        KeyFileList = glob(os.path.join(self.__GitPath,'vpn*/peers/*'))

        for KeyFilePath in KeyFileList:
            SegDir   = os.path.dirname(KeyFilePath).split("/")[-2]
            Segment  = int(SegDir[3:])
            FileName = os.path.basename(KeyFilePath)

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

            if PeerTemplate.match(FileName):
                with open(KeyFilePath,'r') as KeyFile:
                    KeyData  = KeyFile.read()

                    ffNodeID = FileName.lower()[4:]
                    PeerMAC  = None
                    PeerName = ''
                    PeerKey  = None
                    SegMode  = 'auto'

                    for DataLine in KeyData.split('\n'):
                        LowerCharLine = DataLine.lower().strip()

                        if LowerCharLine.startswith('#mac: '):
                            PeerMAC = LowerCharLine[6:]
                            if not MacAdrTemplate.match(PeerMAC):
                                self.__alert('!! Invalid MAC in Key File: %s -> %s' % (KeyFilePath,PeerMAC))
                                PeerMAC = None
                            elif PeerMAC.replace(':','') != ffNodeID:
                                self.__alert('!! Key Filename does not match MAC: %s -> %s' % (KeyFilePath,PeerMAC))

                        elif LowerCharLine.startswith('#hostname: '):
                            PeerName = DataLine[11:]

                        elif LowerCharLine.startswith('#segment: '):
                            SegMode = LowerCharLine[10:]

                        elif LowerCharLine.startswith('key '):
                            PeerKey = LowerCharLine.split(' ')[1][1:-2]
                            if not FastdKeyTemplate.match(PeerKey):
                                self.__alert('!! Invalid Key in Key File: %s -> %s' % (KeyFilePath,PeerKey))
                                PeerKey = None

                        elif not LowerCharLine.startswith('#') and LowerCharLine != '':
                            self.__alert('!! Invalid Entry in Key File: %s -> %s' % (KeyFilePath,DataLine))


                    if PeerMAC is None or PeerKey is None:
                        self.__alert('!! Invalid Key File: %s' % (KeyFilePath))
                    else:
                        if FileName in self.__FastdKeyDict or PeerKey in self.__Key2FileNameDict:
                            self.__alert('!! Duplicate Key File: %s -> %s / %s' % (FileName,SegDir,self.__FastdKeyDict[FileName]['KeyDir']))
                            self.__alert('                       %s = %s/peers/%s -> %s' % (PeerKey,self.__Key2FileNameDict[PeerKey]['KeyDir'],self.__Key2FileNameDict[PeerKey]['KeyFile'],KeyFilePath))
                            self.AnalyseOnly = True
                        elif GwMacTemplate.match(PeerMAC):
                            self.__alert('!! GW Key in Peer Key File: %s -> %s' % (KeyFilePath,PeerMAC))
                        else:
                            self.__FastdKeyDict[FileName] = {
                                'KeyDir'   : SegDir,
                                'SegMode'  : SegMode,
                                'PeerMAC'  : PeerMAC,
                                'PeerName' : PeerName,
                                'PeerKey'  : PeerKey,
                                'VpnMAC'   : None,
                                'VpnGW'    : None,
                                'Timestamp': 0,
                                'DnsSeg'   : None
                            }

                            self.__Key2FileNameDict[PeerKey] = {
                                'KeyDir' : SegDir,
                                'KeyFile': FileName
                            }

            else:
                print('++ Invalid Key Filename: %s' %(KeyFilePath))

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
    def __AnalyseFastdStatus(self,FastdPeersDict,GwName,Segment,HttpTime):

        ActiveKeyCount = 0

        for PeerKey in FastdPeersDict:
            if FastdPeersDict[PeerKey]['connection'] is not None:

                if PeerKey in self.__Key2FileNameDict:
                    KeyFileName = self.__Key2FileNameDict[PeerKey]['KeyFile']

                    if FastdPeersDict[PeerKey]['name'] != KeyFileName:
                        print('!! KeyFile mismatch to Git: %s = %s <> %s\n' % (PeerKey,FastdPeersDict[PeerKey]['name'],KeyFileName))

                    for PeerVpnMAC in FastdPeersDict[PeerKey]['connection']['mac_addresses']:
                        if MacAdrTemplate.match(PeerVpnMAC) and not GwMacTemplate.match(PeerVpnMAC):
                            ActiveKeyCount += 1
                            self.__FastdKeyDict[KeyFileName]['VpnMAC'] = PeerVpnMAC
                            self.__FastdKeyDict[KeyFileName]['VpnGW']  = GwName
                            self.__FastdKeyDict[KeyFileName]['Timestamp'] = HttpTime

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
    def __LoadFastdStatusFile(self,GwName,URL,Segment):

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
    def __GetFastdStatusFileList(self,URL,ffSeg):

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
    # private function "__CheckDNSvsGit"
    #
    #    Returns True if everything is OK
    #
    #--------------------------------------------------------------------------
    def __CheckDNSvsGit(self,DnsZone):

        isOK = True

        DnsKeyRing = dns.tsigkeyring.from_text( {self.__DnsAccDict['ID'] : self.__DnsAccDict['Key']} )
        DnsUpdate  = dns.update.Update(SegAssignDomain, keyring = DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')

        #---------- Check DNS against Git ----------
        print('Checking Peer DNS Entries against Keys in Git ...')
        for DnsName, NodeData in DnsZone.nodes.items():
            for DnsRecord in NodeData.rdatasets:
                DnsPeerID = DnsName.to_text()

                if DnsNodeTemplate.match(DnsPeerID) and DnsRecord.rdtype == dns.rdatatype.AAAA:
                    PeerFileName = DnsPeerID[:16]
                    PeerKeyID    = DnsPeerID[17:]
                    SegFromDNS   = None

                    for DnsAnswer in DnsRecord:
                        IPv6 = DnsAnswer.to_text()

                        if DnsSegTemplate.match(IPv6):
                            if SegFromDNS is None:
                                DnsNodeInfo = IPv6.split(':')
                                SegFromDNS = 'vpn'+DnsNodeInfo[-1].zfill(2)
                            else:
                                self.__alert('!! Duplicate DNS Result: '+DnsPeerID+' = '+IPv6)
                                self.AnalyseOnly = True
                                isOK = False
                        else:
                            self.__alert('!! Invalid DNS IPv6 result: '+DnsPeerID+' = '+IPv6)
                            isOK = False

                    if PeerFileName in self.__FastdKeyDict and SegFromDNS is not None:
                        if self.__FastdKeyDict[PeerFileName]['PeerKey'][:12] == PeerKeyID:
                            self.__FastdKeyDict[PeerFileName]['DnsSeg'] = SegFromDNS

                            if SegFromDNS != self.__FastdKeyDict[PeerFileName]['KeyDir']:
                                self.__alert('!! Segment mismatch DNS <> Git: '+DnsPeerID+' -> '+SegFromDNS+' <> '+self.__FastdKeyDict[PeerFileName]['KeyDir'])
                                self.AnalyseOnly = True
                                isOK = False
                        else:
                            self.__alert('!! Fastd-Key mismatch DNS <> Git: '+DnsPeerID+' -> '+PeerKeyID+' <> '+self.__FastdKeyDict[PeerFileName]['PeerKey'][:12])
                            isOK = False

                            if DnsUpdate is not None:
                                DnsUpdate.delete(DnsPeerID, 'AAAA')
                            else:
                                self.__alert('!! ERROR on updating DNS: '+PeerDnsName+' -> '+PeerDnsIPv6)

                    else:
                        print('++ Unknown or old DNS Entry: '+DnsPeerID+' = '+IPv6)
                        isOK = False

                elif DnsPeerID != '@' and DnsPeerID != '*':
                    self.__alert('!! Invalid DNS Entry: '+DnsPeerID)
                    isOK = False

        #---------- Check Git for missing DNS entries ----------
        print('Checking Keys from Git against DNS Entries ...')

        self.__DnsAccDict['Server']

        for PeerFileName in self.__FastdKeyDict:
            if (PeerTemplate.match(PeerFileName)
            and self.__FastdKeyDict[PeerFileName]['PeerKey'] != ''
            and self.__FastdKeyDict[PeerFileName]['DnsSeg'] != self.__FastdKeyDict[PeerFileName]['KeyDir']):

                self.__alert('!! DNS Entry missing or wrong: '+PeerFileName+' -> '+self.__FastdKeyDict[PeerFileName]['PeerMAC']+' = '+self.__FastdKeyDict[PeerFileName]['PeerName'])

                if DnsUpdate is not None:
                    PeerDnsName = PeerFileName+'-'+self.__FastdKeyDict[PeerFileName]['PeerKey'][:12]
                    PeerDnsIPv6 = '%s%d' % (SegAssignIPv6Prefix,int(self.__FastdKeyDict[PeerFileName]['KeyDir'][3:]))

                    if self.__FastdKeyDict[PeerFileName]['DnsSeg'] is None:
                        DnsUpdate.add(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)
                        print('>>> Adding Peer to DNS:',PeerDnsName,'->',PeerDnsIPv6)
                    else:
                        DnsUpdate.replace(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)
                        print('>>> Updating Peer in DNS:',PeerDnsName,'->',PeerDnsIPv6)

                else:
                    self.__alert('!! ERROR on updating DNS: '+PeerDnsName+' -> '+PeerDnsIPv6)

                isOK = False

        if DnsUpdate is not None:
            if len(DnsUpdate.index) > 1:
                dns.query.tcp(DnsUpdate,self.__DnsServerIP)
                print('... Update launched on DNS-Server',self.__DnsServerIP)

        return isOK



    #--------------------------------------------------------------------------
    # private function "__CheckNodesInSegassignDNS"
    #
    #   Returns True if everything is OK
    #
    #--------------------------------------------------------------------------
    def __CheckNodesInSegassignDNS(self):

        DnsZone     = None
        isOK        = True

        print('\nChecking DNS Zone \"segassign\" ...')

        try:
            DnsResolver = dns.resolver.Resolver()
            self.__DnsServerIP = DnsResolver.query('%s.' % (self.__DnsAccDict['Server']),'a')[0].to_text()
            DnsZone = dns.zone.from_xfr(dns.query.xfr(self.__DnsServerIP,SegAssignDomain))
        except:
            self.__alert('!! ERROR on fetching DNS Zone \"segassign\"!')
            self.__DnsServerIP = None
            self.AnalyseOnly = True
            isOK = False

        if DnsZone is not None:
            isOK = self.__CheckDNSvsGit(DnsZone)
        else:
            isOK = False

        print('... done.\n')
        return isOK



    #=========================================================================
    # public function "GetNodeUplinkInfos"
    #
    #   Returns Dictionary with fastd-Infos
    #
    #=========================================================================
    def GetNodeUplinkInfos(self):

        self.__LoadNodeKeysFromGit()
        self.__LoadFastdStatusInfos()
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
    def MoveNodes(self,NodeMoveDict,GitAccount):

        print('Moving Nodes in GIT and DNS ...')

        if len(NodeMoveDict) < 1:
#        if True:
#            print(NodeMoveDict)
            print('++ There are no Peers to be moved.')
            return

        if self.__DnsServerIP is None or self.__GitPath is None or GitAccount is None:
            print('!! Account Data is not available!')
            return

#        exit(1)

        try:
            GitLockName = os.path.join('/tmp','.'+os.path.basename(self.__GitPath)+'.lock')
            LockFile = open(GitLockName, mode='w+')
            fcntl.lockf(LockFile,fcntl.LOCK_EX)

            DnsKeyRing = dns.tsigkeyring.from_text( {self.__DnsAccDict['ID'] : self.__DnsAccDict['Key']} )
            DnsUpdate  = dns.update.Update(SegAssignDomain, keyring = DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')

            GitRepo   = git.Repo(self.__GitPath)
            GitIndex  = GitRepo.index
            GitOrigin = GitRepo.remotes.origin

            if GitRepo.is_dirty() or len(GitRepo.untracked_files) > 0 or DnsUpdate is None:
                self.__alert('!! The Git Repository and/or DNS are not clean - cannot move Nodes!')
            else:
                self.__alert('++ The following Nodes will be moved automatically:')
                GitCommitMessage = "Automatic move by FFS-Monitor:\n\n"
                MoveCount = 0

                for ffNodeMAC in NodeMoveDict:
                    KeyFileName = 'ffs-'+ffNodeMAC.replace(':','')

                    if KeyFileName in self.__FastdKeyDict:
                        SourceFile = '%s/peers/%s' % (self.__FastdKeyDict[KeyFileName]['KeyDir'], KeyFileName)
                        PeerDnsName = KeyFileName+'-'+self.__FastdKeyDict[KeyFileName]['PeerKey'][:12]

                        if NodeMoveDict[ffNodeMAC] == 999:    # kill this Node
                            DestFile   = '<Trash>'
                        else:
                            DestFile   = 'vpn%02d/peers/%s' % (NodeMoveDict[ffNodeMAC], KeyFileName)

#                        print(SourceFile,'->',DestFile)
                        MoveTextLine = '%s = \"%s\": %s -> vpn%02d' % (KeyFileName,self.__FastdKeyDict[KeyFileName]['PeerName'],self.__FastdKeyDict[KeyFileName]['KeyDir'],NodeMoveDict[ffNodeMAC])
                        print(MoveTextLine)

                        if os.path.exists(os.path.join(self.__GitPath,SourceFile)) and NodeMoveDict[ffNodeMAC] > 0:
                            MoveCount += 1
                            GitCommitMessage += MoveTextLine+'\n'
                            GitIndex.remove([os.path.join(self.__GitPath,SourceFile)])
                            print('... Git remove of old location done.')

                            if NodeMoveDict[ffNodeMAC] == 999:    # kill this Node
                                os.remove(os.path.join(self.__GitPath,SourceFile))
                                DnsUpdate.delete(PeerDnsName, 'AAAA')
                                print('... Node deleted.')
                            else:    # move this Node
                                os.rename(os.path.join(self.__GitPath,SourceFile), os.path.join(self.__GitPath,DestFile))
                                print('... File moved.')
                                GitIndex.add([os.path.join(self.__GitPath,DestFile)])
                                print('... Git add of new location done.')

                                PeerDnsIPv6 = SegAssignIPv6Prefix+str(NodeMoveDict[ffNodeMAC])
                                DnsUpdate.replace(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)

#                            self.__alert('   '+SourceFile+' -> '+DestFile)
                            self.__alert('   %s = %s: %s -> vpn%02d' % (KeyFileName,self.__FastdKeyDict[KeyFileName]['PeerName'],self.__FastdKeyDict[KeyFileName]['KeyDir'],NodeMoveDict[ffNodeMAC]))

                        elif NodeMoveDict[ffNodeMAC] == 0:
                            self.__alert('!! Will not move to Legacy: '+KeyFileName+' = '+ffNodeMAC)
                        else:
                            print('... Key File was already moved by other process.')

                    else:
                        self.__alert('!! Invalid NodeMove Entry: '+KeyFileName+' = '+ffNodeMAC)


                if MoveCount > 0:
                    print('... doing Git commit ...')
#                    GitIndex.commit('Automatic move of node(s) by ffs-Monitor')
                    GitIndex.commit(GitCommitMessage)
                    GitOrigin.config_writer.set('url',GitAccount['URL'])
                    print('... doing Git pull ...')
                    GitOrigin.pull()
                    print('... doing Git push ...')
                    GitOrigin.push()

                    if len(DnsUpdate.index) > 1:
                        dns.query.tcp(DnsUpdate,self.__DnsServerIP)
                        print('DNS Update committed.')
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
