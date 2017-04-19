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
import urllib.request
import time
import datetime
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



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

FreifunkGwDomain    = 'gw.freifunk-stuttgart.de'
FreifunkRootDomain  = 'freifunk-stuttgart.de'

SegAssignDomain     = 'segassign.freifunk-stuttgart.de'
SegAssignIPv6Prefix = '2001:2:0:711::'

GwIgnoreList        = ['gw05n08','gw05n09','gw07', 'gw08n04']

DnsTestTarget       = 'www.google.de'

DnsSegTemplate      = re.compile('^'+SegAssignIPv6Prefix+'(([0-9a-f]{1,4}:){1,2})?[0-9]{1,2}$')
DnsNodeTemplate     = re.compile('^ffs-[0-9a-f]{12}-[0-9a-f]{12}$')

GwNameTemplate      = re.compile('^gw[0-6][0-9]{1,2}')
GwGroupTemplate     = re.compile('^gw[0-6][0-9](s[0-9]{2})?$')
GwInstanceTemplate  = re.compile('^gw[0-6][0-9](n[0-9]{2})?$')
GwSegmentTemplate   = re.compile('^gw[0-6][0-9](n[0-9]{2})?(s[0-9]{2})$')

GwAllMacTemplate    = re.compile('^02:00:((0a)|(3[4-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate    = re.compile('^02:00:3[4-9](:[0-9a-f]{2}){3}')
GwOldMacTemplate    = re.compile('^02:00:0a:3[4-9]:00:[0-9a-f]{2}')

MacAdrTemplate      = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
NodeIdTemplate      = re.compile('^[0-9a-f]{12}$')

PeerTemplate        = re.compile('^ffs-[0-9a-f]{12}')
PeerTemplate1       = re.compile('^ffs[-_][0-9a-f]{12}')
PeerTemplate2       = re.compile('^ffs[0-9a-f]{12}')

SegmentTemplate     = re.compile('^[0-9]{2}$')

KeyDirTemplate      = re.compile('^vpn[0-9]{2}$')
FastdKeyTemplate    = re.compile('^[0-9a-f]{64}$')




class ffGatewayInfo:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,GitPath,DnsAccDict):

        # public Attributes
        self.FastdKeyDict = {}           # FastdKeyDic[KeyFileName]  -> SegDir, VpnMAC, PeerMAC, PeerName, PeerKey
        self.Alerts       = []           # List of  Alert-Messages
        self.AnalyseOnly  = False        # Blocking active Actions due to inconsistent Data

        # private Attributes
        self.__GitPath     = GitPath
        self.__DnsAccDict  = DnsAccDict  # DNS Account
        self.__DnsServerIP = None

        self.__GatewayDict = {}          # GatewayDict[GwInstanceName] -> IPs, Segments
        self.__SegmentDict = {}          # SegmentDict[SegmentNumber]  -> GwGitNames, GwDnsNames, GwBatNames, GwIPs
        self.__GwAliasDict = {}          # GwAliasDict[LegacyName]     -> current new Gateway
        self.__Key2FileNameDict = {}     # Key2FileNameDict[PeerKey]   -> SegDir, KeyFileName

        # Initializations
        self.__GetGatewaysFromGit()
        self.__GetGatewaysFromDNS()
        self.__CheckGwLegacyDnsEntries()
        self.__GetGatewaysFromBatman()

        self.__CheckGatewayDnsServer()

        self.__LoadKeysFromGit()
        self.__LoadFastdStatusInfos()
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
    # private function "__GetGatewaysFromGit"
    #
    #   Load and analyse Gateway-Files from Git
    #
    #-----------------------------------------------------------------------
    def __GetGatewaysFromGit(self):

        print('Loading Gateways from Git ...')

        GitLockName = os.path.join('/tmp','.'+os.path.basename(self.__GitPath)+'.lock')

        try:
            LockFile = open(GitLockName, mode='w+')
            fcntl.lockf(LockFile,fcntl.LOCK_EX)
            GitRepo   = git.Repo(self.__GitPath)
            GitOrigin = GitRepo.remotes.origin

            if not GitRepo.is_dirty():
                print('... Git pull ...')
                GitOrigin.pull()
            else:
                self.AnalyseOnly = True
                self.__alert('!! Git Repository is dirty - switched to analyse only mode!')

            for SegDir in os.listdir(self.__GitPath):
                SegPath = os.path.join(self.__GitPath,SegDir)

                if os.path.isdir(SegPath) and SegDir[:3] == 'vpn':
                    Segment = int(SegDir[3:])

                    if Segment not in self.__SegmentDict:
                        self.__SegmentDict[Segment] = { 'GwGitNames':[], 'GwDnsNames':[], 'GwBatNames':[], 'GwIPs':[] }
#                        print('>>> New Segment =',Segment)

                    VpnBackbonePath = os.path.join(SegPath,'bb')

                    if os.path.isdir(VpnBackbonePath):
                        for KeyFileName in os.listdir(VpnBackbonePath):
                            if GwSegmentTemplate.match(KeyFileName):
                                self.__SegmentDict[Segment]['GwGitNames'].append(KeyFileName.split('s')[0])

        except:
            self.__alert('!! Fatal ERROR on accessing Git for Gateways!')
        finally:
            del GitOrigin
            del GitRepo

            fcntl.lockf(LockFile,fcntl.LOCK_UN)
            LockFile.close()

#        print()
#        for Segment in sorted(self.__SegmentDict):
#            print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwGitNames'])))

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
            for DnsType in ['a','aaaa']:
                try:
                    DnsResult = DnsResolver.query(DnsName,DnsType)
                except:
                    DnsResult = None

                if DnsResult is not None:
                    for GatewayIP in DnsResult:
#                        print('>>> GwIP:',GatewayIP)  #................................................
                        IpList.append(GatewayIP.to_text())

            try:
                DnsResult = DnsResolver.query(DnsName,'cname')
            except:
                DnsResult = None

            if DnsResult is not None:
                for Cname in DnsResult:
                    GwName = Cname.to_text()
                    print('>>> GwName/Cname:',GwName)  #................................................
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



    #==========================================================================
    # private function "__GetGatewaysFromDNS"
    #
    #   Result = __GatewayDict[GwInstanceName] -> IPs and Segments for the GW
    #
    #--------------------------------------------------------------------------
    def __GetGatewaysFromDNS(self):

        print('Checking DNS for Gateways:',FreifunkGwDomain,'...\n')

        Ip2GwDict   = {}
        DnsZone     = None

        try:
            DnsResolver = dns.resolver.Resolver()
            DnsServerIP = DnsResolver.query('%s.' % (self.__DnsAccDict['Server']),'a')[0].to_text()
            DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,FreifunkGwDomain))
        except:
            self.__alert('!! ERROR on fetching DNS Zone: '+FreifunkGwDomain)
            DnsZone = None
            self.AnalyseOnly = True

        if DnsZone is None:
            print('++ DNS Zone is empty:',FreifunkGwDomain)

        else:
            #----- get Gateways from Zone File -----
            for name, node in DnsZone.nodes.items():
                GwName = name.to_text()

                if GwInstanceTemplate.match(GwName):
                    if GwName not in self.__GatewayDict:
                        self.__GatewayDict[GwName] = { 'IPs':[],'Segments':[] }

                    self.__GetGwInstances(GwName,FreifunkGwDomain,node.rdatasets)

                if GwGroupTemplate.match(GwName):
                    if len(GwName) == 7:
                        Segment = int(GwName[5:])
                    else:
                        Segment = 0    # legacy names -> will be used for onboarding

                    if Segment not in self.__SegmentDict:
                        print('!! Segment in DNS but not in Git:',Segment)
                        self.__SegmentDict[Segment] = { 'GwGitNames':[], 'GwDnsNames':[], 'GwIPs':[], 'GwBatNames':[] }

                    self.__SegmentDict[Segment]['GwIPs'] += self.__GetSegmentGwIPs(FreifunkGwDomain,node.rdatasets)

            #----- setting up GwIP to GwInstanceName -----
            for GwName in self.__GatewayDict:
                for GwIP in self.__GatewayDict[GwName]['IPs']:
                    if GwIP not in Ip2GwDict:
                        Ip2GwDict[GwIP] = GwName
                    else:
                        if Ip2GwDict[GwIP][:4] == GwName[:4] and len(GwName) != len(Ip2GwDict[GwIP]):
                            print('++ Gateway Alias:',GwIP,'=',GwName,'=',Ip2GwDict[GwIP])

                            if len(GwName) > len(Ip2GwDict[GwIP]):    # longer name is new name
                                self.__GwAliasDict[Ip2GwDict[GwIP]] = GwName
                                Ip2GwDict[GwIP] = GwName
                            else:
                                self.__GwAliasDict[GwName] = Ip2GwDict[GwIP]
                        else:
                            print('!! Duplicate Gateway IP:',GwIP,'=',Ip2GwDict[GwIP],'<>',GwName)

            for GwName in self.__GwAliasDict:
                del self.__GatewayDict[GwName]


            #----- setting up Segment to GwInstanceNames -----
            print()
            for Segment in sorted(self.__SegmentDict.keys()):
#                print('>>>',Segment,'->',self.__SegmentDict[Segment]['GwIPs'])

                for GwIP in self.__SegmentDict[Segment]['GwIPs']:
                    if GwIP in Ip2GwDict:
                        GwName = Ip2GwDict[GwIP]

                        if GwName not in self.__SegmentDict[Segment]['GwDnsNames']:
                            self.__SegmentDict[Segment]['GwDnsNames'].append(GwName)

                            if GwName not in self.__SegmentDict[Segment]['GwGitNames'] and Segment > 0:
                                self.__alert('!! DNS entry without Key in Git: '+GwName+' -> '+str(Segment))

                            if Segment not in self.__GatewayDict[GwName]['Segments']:
                                self.__GatewayDict[GwName]['Segments'].append(Segment)
                            else:
                                self.__alert('!! DNS entries are inconsistent: '+GwName+' -> '+str(Segment))
                    else:
                        self.__alert('!! Unknown Gateway IP: '+GwIP)

                print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwDnsNames'])))

                if Segment > 0 and Segment < 9 and len(self.__SegmentDict[Segment]['GwDnsNames']) < 1:
                    self.__alert('!! No Gateways in Segment '+str(Segment).zfill(2)+' !')

            print()
            for GwName in sorted(self.__GatewayDict):
                print(GwName,'->',sorted(self.__GatewayDict[GwName]['Segments']))

            print()
            for GwIP in sorted(Ip2GwDict):
                print(GwIP,'->',Ip2GwDict[GwIP])

        print('\n... done.\n')
        return




    #==========================================================================
    # private function "__CheckGwLegacyDnsEntries"
    #
    #--------------------------------------------------------------------------
    def __CheckGwLegacyDnsEntries(self):

        print('Checking DNS for Legacy Gateway entries:',FreifunkRootDomain,'...')

        Seg2GwIpDict = {}
        DnsZone      = None

        try:
            DnsResolver = dns.resolver.Resolver()
            DnsServerIP = DnsResolver.query('%s.' % (self.__DnsAccDict['Server']),'a')[0].to_text()
            DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,FreifunkRootDomain))
        except:
            self.__alert('!! ERROR on fetching DNS Zone: '+FreifunkRootDomain)
            DnsZone = None
            self.AnalyseOnly = True

        if DnsZone is None:
            print('++ DNS Zone is empty:',FreifunkRootDomain)

        else:
            #----- get Gateways from Zone File -----
            for name, node in DnsZone.nodes.items():
                GwName = name.to_text()

                if GwGroupTemplate.match(GwName):
                    if len(GwName) == 7:
                        Segment = int(GwName[5:])
                    else:
                        Segment = 0    # legacy names -> will be used for onboarding

                    if Segment not in self.__SegmentDict:
                        print('!! Invalid Segment:',Segment)
                    else:
                        if Segment not in Seg2GwIpDict:
                            Seg2GwIpDict[Segment] = []

                        GwIPs = self.__GetSegmentGwIPs(FreifunkRootDomain,node.rdatasets)

#                        print('>>>',GwName,'->',GwIPs)
                        Seg2GwIpDict[Segment] += GwIPs

#            print()
            for Segment in sorted(Seg2GwIpDict):
#                print(Segment,'->',Seg2GwIpDict[Segment])

                for SegIP in Seg2GwIpDict[Segment]:
                    if SegIP not in self.__SegmentDict[Segment]['GwIPs']:
                        print('!! Invalid IP-Address for Gateway:',Segment,'->',SegIP)

            for Segment in sorted(self.__SegmentDict):
                if Segment < 9:
                    for SegIP in self.__SegmentDict[Segment]['GwIPs']:
                        if SegIP not in Seg2GwIpDict[Segment]:
                            print('!! Missing IP-Address of Gateway:',Segment,'->',SegIP)

        print('\n... done.\n')
        return




    #--------------------------------------------------------------------------
    # private function "__GetSegmentGwListFromBatman"
    #
    #    Returns List of Gateways in given Segment
    #
    #--------------------------------------------------------------------------
    def __GetSegmentGwListFromBatman(self,Segment):

        BatmanIF  = 'bat%02d' % (Segment)
        BatResult = None
        GwList    = []

        try:
            BatctlGwl = subprocess.run(['/usr/sbin/batctl','-m',BatmanIF,'gwl'], stdout=subprocess.PIPE)
            BatResult = BatctlGwl.stdout.decode('utf-8')
        except:
            print('!! ERROR on batctl -m',BatmanIF)
            BatResult = None

        if BatResult is not None:
            for BatLine in BatResult.split('\n'):
                GwName = None
                GwMAC = BatLine.strip()[:17]

                if GwNewMacTemplate.match(GwMAC):      # e.g. "02:00:38:12:08:06"
                    if int(GwMAC[9:11]) == Segment:
                        GwName = 'gw'+GwMAC[12:14]+'n'+GwMAC[15:17]
                    else:
                        self.__alert('!! Shortcut detected: '+BatmanIF+' -> '+GwMAC)

                elif GwOldMacTemplate.match(GwMAC):    # e.g. "02:00:0a:38:00:09"
                    if Segment == 0:
                        GwName = 'gw'+GwMAC[15:17]
                        if GwName in self.__GwAliasDict:
                            GwName = self.__GwAliasDict[GwName]

                        print('++ Old Gateway MAC:',BatmanIF,'->',GwMAC,'=',GwName)
                    else:
                        self.__alert('!! Shortcut detected: '+BatmanIF+' -> '+GwMAC)

                elif MacAdrTemplate.match(GwMAC):
                    self.__alert('!! Invalid Gateway MAC: '+BatmanIF+' -> '+GwMAC)

                if GwName is not None:
                    if GwName not in GwList:
                        GwList.append(GwName)
                    else:
#                        self.__alert('!! Duplicate Gateway MAC: '+BatmanIF+' -> '+GwMAC)
                        print('!! Duplicate Gateway MAC: '+BatmanIF+' -> '+GwMAC)

        return GwList



    #==========================================================================
    # private function "__GetGatewaysFromBatman"
    #
    #   Result = __GatewayDict[GwInstanceName] -> IPs and Segments for the GW
    #
    #--------------------------------------------------------------------------
    def __GetGatewaysFromBatman(self):

        print('\nChecking Batman for Gateways ...\n')

        for Segment in sorted(self.__SegmentDict):
            GwList = self.__GetSegmentGwListFromBatman(Segment)

            for GwName in GwList:
                if GwName not in self.__GatewayDict:
                    self.__GatewayDict[GwName] = { 'IPs':[],'Segments':[] }
                    print('++ Inofficial Gateway found:',GwName)

                if Segment not in self.__GatewayDict[GwName]['Segments']:
                    self.__GatewayDict[GwName]['Segments'].append(Segment)

                if GwName not in self.__SegmentDict[Segment]['GwBatNames']:
                    self.__SegmentDict[Segment]['GwBatNames'].append(GwName)

            for GwName in self.__SegmentDict[Segment]['GwDnsNames']:
                if GwName not in self.__SegmentDict[Segment]['GwBatNames']:
                    print('!! Gateway in DNS but not in Batman:',Segment,GwName)

        print()
        for Segment in sorted(self.__SegmentDict):
            print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwBatNames'])))

        print()
        for GwName in sorted(self.__GatewayDict):
            print(GwName,'->',sorted(self.__GatewayDict[GwName]['Segments']))

        print('\n... done.\n')
        return



    #==========================================================================
    # private function "__CheckGatewayDnsServer"
    #
    #
    #--------------------------------------------------------------------------
    def __CheckGatewayDnsServer(self):

        print('\nChecking DNS-Server on Gateways ...')

        DnsResolver = None

        try:
            DnsResolver = dns.resolver.Resolver()
        except:
            DnsResolver = None

        if DnsResolver is not None:
            for Segment in sorted(self.__SegmentDict.keys()):
                if Segment > 0:
                    for GwName in sorted(self.__SegmentDict[Segment]['GwBatNames']):
                        if len(GwName) == 7 and GwName not in ['gw05n01']:
                            InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int(Segment/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
                            InternalGwIPv6 = 'fd21:b4dc:4b%02d::a38:%d' % ( Segment, int(GwName[2:4])*100 + int(GwName[6:8]) )

#                            for DnsServer in [InternalGwIPv4,InternalGwIPv6]:
                            for DnsServer in [InternalGwIPv4]:
                                DnsResolver.nameservers = [DnsServer]

                                for DnsType in ['a','aaaa']:
                                    try:
                                        DnsResult = DnsResolver.query(DnsTestTarget,DnsType)
                                    except:
                                        DnsResult = None

                                    if DnsResult is None:
                                        print('!! Error on DNS-Server:',Segment,'->',GwName,'=',DnsServer,'->',DnsTestTarget,'/',DnsType)

        print('... done.\n')
        return



    #-----------------------------------------------------------------------
    # private function "__LoadKeyFile"
    #
    #   Load and analyse fastd-Keyfile from Git
    #
    # GitPeerDict[KeyFileName] -> SegDir, PeerMAC, PeerName, PeerKey
    #-----------------------------------------------------------------------
    def __LoadKeyFile(self,SegDir,KeyFileName):

        PeerMAC = ''
        PeerName = ''
        PeerKey = ''
        SegMode = 'auto'

        KeyFilePath = os.path.join(SegDir,'peers',KeyFileName)
        PeerInFile  = open(os.path.join(self.__GitPath,KeyFilePath), 'r', 1, 'utf-8')

        for PeerData in PeerInFile:
            PeerLine = PeerData.rstrip('\n')

            if PeerLine[:6].lower() == '#mac: ':
                if MacAdrTemplate.match(PeerLine[6:23]):
                    PeerMAC = PeerLine[6:23]
                elif NodeIdTemplate.match(PeerLine[6:18]):
                    PeerMAC = PeerLine[6:8] + ':' + PeerLine[8:10] + ':' + PeerLine[10:12] + ':' + PeerLine[12:14] + ':' + PeerLine[14:16] + ':' + PeerLine[16:18]
                    print('++ Peer MAC invalid Format:', KeyFilePath, '=', PeerMAC)
                else:
                    print('++ Peer MAC invalid contents:', KeyFilePath, '=', PeerLine)
            elif PeerLine[:11].lower() == '#hostname: ':
                PeerName = PeerLine[11:]
            elif PeerLine[:10].lower() == '#segment: ':
                SegMode = PeerLine[10:].lower()
            elif PeerLine[:4].lower() == 'key ':
                PeerKey = PeerLine[5:69]

        PeerInFile.close()

        if not FastdKeyTemplate.match(PeerKey):
            print('++ Invalid PeerKey:', KeyFilePath, '=', PeerKey, PeerMAC, PeerName.encode('utf-8'))
            return

        PeerFileMAC = ''

        if PeerTemplate1.match(KeyFileName):
            PeerFileMAC = KeyFileName[4:6] + ':' + KeyFileName[6:8] + ':' + KeyFileName[8:10] + ':' + KeyFileName[10:12] + ':' + KeyFileName[12:14] + ':' + KeyFileName[14:16]
        elif PeerTemplate2.match(KeyFileName):
            PeerFileMAC = KeyFileName[3:5] + ':' + KeyFileName[5:7] + ':' + KeyFileName[7:9] + ':' + KeyFileName[9:11] + ':' + KeyFileName[11:13] + ':' + KeyFileName[13:15]

        if PeerMAC == '':
            if MacAdrTemplate.match(PeerName):
                PeerMAC = PeerName
                PeerName = ''
                print('++ PeerHostName is PeerMAC:', KeyFilePath, '=', PeerMAC, PeerName)
            elif PeerTemplate1.match(PeerName):
                PeerMAC = PeerName[4:6] + ':' + PeerName[6:8] + ':' + PeerName[8:10] + ':' + PeerName[10:12] + ':' + PeerName[12:14] + ':' + PeerName[14:16]
                if PeerFileMAC != '' and PeerMAC != PeerFileMAC:
                    print('++ MAC of KeyFileName doesn\'t match Hostname \#1:', KeyFilePath, '=', PeerMAC, PeerName)
            elif PeerTemplate2.match(PeerName):
                PeerMAC = PeerName[3:5] + ':' + PeerName[5:7] + ':' + PeerName[7:9] + ':' + PeerName[9:11] + ':' + PeerName[11:13] + ':' + PeerName[13:15]
                if PeerFileMAC != '' and PeerMAC != PeerFileMAC:
                    print('++ MAC of KeyFileName doesn\'t match Hostname \#2:', KeyFilePath, '=', PeerMAC, PeerName)
            elif PeerFileMAC != '':
                PeerMAC = PeerFileMAC
            else:
                print('++ No PeerMAC found:', KeyFilePath)
        elif PeerFileMAC != '' and PeerFileMAC != PeerMAC:
            print('++ KeyFileName doesn\'t match PeerMAC:', KeyFilePath, '=', PeerMAC, PeerName)

        if KeyFileName in self.FastdKeyDict:
            self.__alert('!! Duplicate KeyFile: '+KeyFileName+' = '+SegDir+' + '+self.FastdKeyDict[KeyFileName]['SegDir'])
            self.AnalyseOnly = True

            if self.FastdKeyDict[KeyFileName]['PeerMAC'] != PeerMAC:
                print('!! Different PeerMAC:',KeyFileName,'=',PeerMAC,'<>',self.FastdKeyDict[KeyFileName]['PeerMAC'])

            if self.FastdKeyDict[KeyFileName]['PeerName'] != PeerName:
                print('!! Different PeerName:',KeyFileName,'=',PeerName.encode('utf-8'),'<>',self.FastdKeyDict[KeyFileName]['PeerName'].encode('utf-8'))

            if self.FastdKeyDict[KeyFileName]['PeerKey'] != PeerKey:
                print('!! Different PeerKey:',KeyFileName,'=',PeerKey,'<>',self.FastdKeyDict[KeyFileName]['PeerKey'])

        self.FastdKeyDict[KeyFileName] = {
            'SegDir':SegDir,
            'SegMode':SegMode,
            'PeerMAC':PeerMAC,
            'PeerName':PeerName,
            'PeerKey':PeerKey,
            'VpnMAC':'',
            'LastConn':0,
            'DnsSeg':None
        }

        if PeerKey != '' and PeerKey in self.__Key2FileNameDict:
            self.__alert('!! Duplicate fastd-Key: '+PeerKey+' = '+self.__Key2FileNameDict[PeerKey]['SegDir']+'/peers/'+self.__Key2FileNameDict[PeerKey]['KeyFile']+' -> '+SegDir+'/peers/'+KeyFileName)
            self.AnalyseOnly = True

        self.__Key2FileNameDict[PeerKey] = {
            'SegDir':SegDir,
            'KeyFile':KeyFileName
        }

        return



    #=======================================================================
    # private function "__LoadKeysFromGit"
    #
    #   Load and analyse fastd-Keys from Git
    #
    #     self.FastdKeyDict[KeyFileName] = { 'SegDir','PeerMAC','PeerName','PeerKey' }
    #     self.__Key2FileNameDict[PeerKey]    = { 'SegDir','KeyFile' }
    #
    #-----------------------------------------------------------------------
    def __LoadKeysFromGit(self):

        print('Load and analyse fastd-Keys from Git ...')

        for SegDir in os.listdir(self.__GitPath):
            SegPath = os.path.join(self.__GitPath,SegDir)

            if os.path.isdir(SegPath) and SegDir[:3] == 'vpn':
                Segment = int(SegDir[3:])

                if Segment not in self.__SegmentDict:
                    self.__SegmentDict[Segment] = { 'GwGitNames':[], 'GwDnsNames':[], 'GwBatNames':[], 'GwIPs':[] }
                    print('!! Segment without Gateway:',Segment)

                VpnPeerPath = os.path.join(SegPath,'peers')

                for KeyFileName in os.listdir(VpnPeerPath):
                    if KeyFileName[:1] != '.':
                        if not PeerTemplate.match(KeyFileName):
                            print('++ Invalid Key Filename:', os.path.join(SegDir,'peers',KeyFileName))

                        if GwNameTemplate.match(KeyFileName):
                            print('++ GW in peer folder:',os.path.join(SegDir,'peers',KeyFileName))
                        else:
                            self.__LoadKeyFile(SegDir,KeyFileName)

        print('... done.\n')
        return




    #-----------------------------------------------------------------------
    # private function "__AnalyseFastdStatus"
    #
    #   Analyse fastd-status.json
    #
    # FastdKey -> { URL, KeyFile, MAC }
    #
    #-----------------------------------------------------------------------
    def __AnalyseFastdStatus(self,FastdPeersDict,Segment,LastConnected):

        ActiveKeyCount = 0

        for PeerKey in FastdPeersDict:
            if FastdPeersDict[PeerKey]['name'] is not None and FastdPeersDict[PeerKey]['connection'] is not None:

                if FastdPeersDict[PeerKey]['name'] in self.FastdKeyDict:

                    if PeerKey != self.FastdKeyDict[FastdPeersDict[PeerKey]['name']]['PeerKey']:
                        print('!! PeerKey mismatch to Git:',FastdPeersDict[PeerKey]['name'],'=',PeerKey,'<>',self.FastdKeyDict[FastdPeersDict[PeerKey]['name']]['PeerKey'])
                        print()

                    elif PeerKey in self.__Key2FileNameDict:
                        if FastdPeersDict[PeerKey]['name'] != self.__Key2FileNameDict[PeerKey]['KeyFile']:
                            print('!! KeyFile mismatch to Git:',PeerKey,'=',FastdPeersDict[PeerKey]['name'],'<>',self.__Key2FileNameDict[PeerKey]['KeyFile'])
                            print()

                        else:   # Key and Filename found in Git
                            for PeerVpnMAC in FastdPeersDict[PeerKey]['connection']['mac_addresses']:
                                if PeerVpnMAC != '' and not GwAllMacTemplate.match(PeerVpnMAC):
                                    ActiveKeyCount += 1
                                    self.FastdKeyDict[FastdPeersDict[PeerKey]['name']]['VpnMAC'] = PeerVpnMAC
                                    self.FastdKeyDict[FastdPeersDict[PeerKey]['name']]['LastConn'] = LastConnected

                    else:
                        print('!! PeerKey not in FastdKeyDict:',FastdPeersDict[PeerKey]['name'],'=',PeerKey)
                        print()

                elif PeerTemplate1.match(FastdPeersDict[PeerKey]['name']):
                    print('!! PeerKey not in Git:',FastdPeersDict[PeerKey]['name'],'=',PeerKey)
                    print()

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
    def __LoadFastdStatusFile(self,URL,Segment):

        ActiveConnections = 0

        try:
            FastdJsonHTTP = urllib.request.urlopen(URL,timeout=5)
            HttpDate = datetime.datetime.strptime(FastdJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate
            jsonFastdDict = json.loads(FastdJsonHTTP.read().decode('utf-8'))
            FastdJsonHTTP.close()
        except:
#            print('++ ERROR fastd status connect!',URL)
            return None
        else:
            StatusAge = datetime.datetime.utcnow() - HttpDate

            if StatusAge.total_seconds() < 900:
                if 'peers' in jsonFastdDict:
                    if 'interface' in jsonFastdDict:
                        if int(jsonFastdDict['interface'][3:5]) != Segment:
                            print('!! Bad Interface in fastd status file:',URL,'=',jsonFastdDict['interface'],'->',Segment)
                            return None

                    LastConnTime = int(time.mktime(HttpDate.timetuple()))
                    ActiveConnections = self.__AnalyseFastdStatus(jsonFastdDict['peers'],Segment,LastConnTime)
                else:
                    print('!! Bad fastd status file!',URL)
            else:
                print('++ fastd status to old!',URL)

        return ActiveConnections



    #==========================================================================
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
        print('Loading fastd Status Infos ...')

        for GwName in sorted(self.__GatewayDict):
            if len(self.__GatewayDict[GwName]['Segments']) > 0 : print()

            if GwName not in GwIgnoreList:
                for ffSeg in sorted(self.__GatewayDict[GwName]['Segments']):
                    FastdJsonURL = 'http://%s.%s/data/vpn%02d.json' % (GwName,FreifunkGwDomain,ffSeg)
                    ActiveConnections = self.__LoadFastdStatusFile(FastdJsonURL,ffSeg)
                    print('...',GwName,ffSeg,'=',ActiveConnections)

                    if GwName[:4] == 'gw05':  # on gw05 we have separate fastd instances for IPv4 and IPv6
                        FastdJsonURL = 'http://%s.%s/data/vpn%02dip6.json' % (GwName,FreifunkGwDomain,ffSeg)
                        ActiveConnections = self.__LoadFastdStatusFile(FastdJsonURL,ffSeg)
                        print('...',GwName,ffSeg,'(IPv6) =',ActiveConnections)

            else:
                print('...',GwName,'... ignored.')

        print('... done.')
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

                    if PeerFileName in self.FastdKeyDict and not SegFromDNS is None:
                        if self.FastdKeyDict[PeerFileName]['PeerKey'][:12] == PeerKeyID:
                            self.FastdKeyDict[PeerFileName]['DnsSeg'] = SegFromDNS

                            if SegFromDNS != self.FastdKeyDict[PeerFileName]['SegDir']:
                                self.__alert('!! Segment mismatch DNS <> Git: '+DnsPeerID+' -> '+SegFromDNS+' <> '+self.FastdKeyDict[PeerFileName]['SegDir'])
                                self.AnalyseOnly = True
                                isOK = False
                        else:
                            self.__alert('!! Fastd-Key mismatch DNS <> Git: '+DnsPeerID+' -> '+PeerKeyID+' <> '+self.FastdKeyDict[PeerFileName]['PeerKey'][:12])
                            isOK = False

                    else:
                        print('++ Unknown or old DNS Entry: '+DnsPeerID+' = '+IPv6)
                        isOK = False

                elif DnsPeerID != '@':
                    self.__alert('!! Invalid DNS Entry: '+DnsPeerID)
                    isOK = False

        #---------- Check Git for missing DNS entries ----------
        print('Checking Keys from Git against DNS Entries ...')

        self.__DnsAccDict['Server']

        DnsKeyRing = None
        DnsUpdate  = None

        for PeerFileName in self.FastdKeyDict:
            if ((PeerTemplate.match(PeerFileName)) and
                (self.FastdKeyDict[PeerFileName]['PeerKey'] != '') and
                (self.FastdKeyDict[PeerFileName]['SegDir'] != 'vpn00') and
                (self.FastdKeyDict[PeerFileName]['DnsSeg'] is None)):

                self.__alert('!! DNS Entry missing: '+PeerFileName+' -> '+self.FastdKeyDict[PeerFileName]['PeerMAC']+' = '+self.FastdKeyDict[PeerFileName]['PeerName'])

                if DnsUpdate is None:
                    DnsKeyRing = dns.tsigkeyring.from_text( {self.__DnsAccDict['ID'] : self.__DnsAccDict['Key']} )
                    DnsUpdate  = dns.update.Update(SegAssignDomain, keyring = DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')

                if DnsUpdate is not None:
                    PeerDnsName = PeerFileName+'-'+self.FastdKeyDict[PeerFileName]['PeerKey'][:12]
                    PeerDnsIPv6 = '%s%d' % (SegAssignIPv6Prefix,int(self.FastdKeyDict[PeerFileName]['SegDir'][3:]))
                    DnsUpdate.add(PeerDnsName, 300, 'AAAA',PeerDnsIPv6)
                    print('>>> Adding Peer to DNS:',PeerDnsName,'->',PeerDnsIPv6)

                isOK = False

        if DnsUpdate is not None:
            dns.query.tcp(DnsUpdate,self.__DnsServerIP)

        return isOK



    #=========================================================================
    # Method "CheckNodesInDNS"
    #
    #   Returns True if everything is OK
    #
    #=========================================================================
    def CheckNodesInDNS(self):

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
    # Method "Segments"
    #
    #   Returns List of Segments
    #
    #=========================================================================
    def Segments(self):
        return self.__SegmentDict.keys()



    #==============================================================================
    # Method "MoveNodes"
    #
    #   Moving Nodes in GIT and DNS
    #==============================================================================
    def MoveNodes(self,NodeMoveDict,GitAccount):

        print('Moving Nodes in GIT and DNS ...')

        if len(NodeMoveDict) < 1:
            print('++ There are no Peers to be moved.')
            return

        if self.__DnsServerIP is None or self.__GitPath is None or GitAccount is None:
            print('!! Account Data is not available!')
            return


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
                MoveCount = 0

                for ffNodeMAC in NodeMoveDict:
                    KeyFileName = 'ffs-'+ffNodeMAC.replace(':','')

                    if KeyFileName in self.FastdKeyDict:
                        SourceFile = '%s/peers/%s' % (self.FastdKeyDict[KeyFileName]['SegDir'], KeyFileName)
                        PeerDnsName = KeyFileName+'-'+self.FastdKeyDict[KeyFileName]['PeerKey'][:12]

                        if NodeMoveDict[ffNodeMAC] == 999:    # kill this Node
                            DestFile   = '<Trash>'
                        else:
                            DestFile   = 'vpn%02d/peers/%s' % (NodeMoveDict[ffNodeMAC], KeyFileName)

                        print(SourceFile,'->',DestFile)

                        if os.path.exists(os.path.join(self.__GitPath,SourceFile)) and NodeMoveDict[ffNodeMAC] > 0:
                            MoveCount += 1
                            GitIndex.remove([os.path.join(self.__GitPath,SourceFile)])
                            print('... Git remove of old location done.')

                            if NodeMoveDict[ffNodeMAC] == 999:    # kill this Node
                                os.remove(os.path.join(self.__GitPath,SourceFile))
                                print('... File deleted.')

                                if self.FastdKeyDict[KeyFileName]['SegDir'] != 'vpn00':
                                    DnsUpdate.delete(PeerDnsName, 'AAAA')

                            else:    # move this Node
                                os.rename(os.path.join(self.__GitPath,SourceFile), os.path.join(self.__GitPath,DestFile))
                                print('... File moved.')
                                GitIndex.add([os.path.join(self.__GitPath,DestFile)])
                                print('... Git add of new location done.')

                                PeerDnsIPv6 = SegAssignIPv6Prefix+str(NodeMoveDict[ffNodeMAC])

                                if self.FastdKeyDict[KeyFileName]['SegDir'] == 'vpn00':
                                    DnsUpdate.add(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)
                                else:
                                    DnsUpdate.replace(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)

                            self.__alert('   '+SourceFile+' -> '+DestFile)

                        elif NodeMoveDict[ffNodeMAC] == 0:
                            self.__alert('!! Will not move to Legacy: '+KeyFileName+' = '+ffNodeMAC)
                        else:
                            print('... Key File was already moved by other process.')

                    else:
                        self.__alert('!! Invalid NodeMove Entry: '+KeyFileName+' = '+ffNodeMAC)


                if MoveCount > 0:
                    print('... doing Git commit ...')
                    GitIndex.commit('Automatic move of node(s) by ffs-Monitor')
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
