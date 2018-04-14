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
#  Copyright (c) 2017-2018, Roland Volkmann <roland.volkmann@t-online.de>                 #
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

from glob import glob



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

FreifunkGwDomain    = 'gw.freifunk-stuttgart.de'
FreifunkRootDomain  = 'freifunk-stuttgart.de'

SegAssignDomain     = 'segassign.freifunk-stuttgart.de'
SegAssignIPv6Prefix = '2001:2:0:711::'

GwIgnoreList        = ['gw04','gw04n03','gw05n01','gw05n08','gw05n09','gw07']

DnsTestTarget       = 'www.google.de'

DnsSegTemplate      = re.compile('^'+SegAssignIPv6Prefix+'(([0-9a-f]{1,4}:){1,2})?[0-9]{1,2}$')
DnsNodeTemplate     = re.compile('^ffs-[0-9a-f]{12}-[0-9a-f]{12}$')

GwNameTemplate      = re.compile('^gw[0-6][0-9]{1,2}')
GwGroupTemplate     = re.compile('^gw[0-6][0-9](s[0-9]{2})?$')
GwInstanceTemplate  = re.compile('^gw[0-6][0-9](n[0-9]{2})?$')
GwSegmentTemplate   = re.compile('^gw[0-6][0-9](n[0-9]{2})?(s[0-9]{2})$')

GwAllMacTemplate    = re.compile('^02:00:((0a)|(3[1-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate    = re.compile('^02:00:3[1-9](:[0-9a-f]{2}){3}')
GwOldMacTemplate    = re.compile('^02:00:0a:3[1-9]:00:[0-9a-f]{2}')

MacAdrTemplate      = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
NodeIdTemplate      = re.compile('^[0-9a-f]{12}$')

PeerTemplate        = re.compile('^ffs-[0-9a-f]{12}')

SegmentTemplate     = re.compile('^[0-9]{2}$')
KeyDirTemplate      = re.compile('^vpn[0-9]{2}$')

FastdKeyTemplate    = re.compile('^[0-9a-f]{64}$')


BATMAN_DEBUG_FILES  = '/sys/kernel/debug/batman_adv'
BATMAN_GATEWAYS     = 'gateways'



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

        self.__GatewayDict = {}          # GatewayDict[GwInstanceName] -> IPs, DnsSegments, BatmanSegments
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

            GwFileList = glob(os.path.join(self.__GitPath,'vpn*/bb/gw*'))

            for KeyFilePath in GwFileList:
                Segment  = int(os.path.dirname(KeyFilePath).split("/")[-2][3:])
                FileName = os.path.basename(KeyFilePath)

                if Segment == 0:
                    continue    # >>>>>>>>>>>>>>>> no Legacy !!!!!!!!!!!!!!!!!

                if Segment not in self.__SegmentDict:
                    self.__SegmentDict[Segment] = { 'GwGitNames':[], 'GwDnsNames':[], 'GwBatNames':[], 'GwIPs':[] }

                if GwSegmentTemplate.match(FileName):
                    if int(FileName.split('s')[1]) == Segment:
                        self.__SegmentDict[Segment]['GwGitNames'].append(FileName.split('s')[0])
                    else:
                        print('++ Invalid File Name in Git:',KeyFilePath)
                else:
                    print('!! Bad File in Git:',KeyFilePath)

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
#        exit(1)

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
                        self.__GatewayDict[GwName] = { 'IPs':[], 'DnsSegments':[], 'BatmanSegments':[] }

                    self.__GetGwInstances(GwName,FreifunkGwDomain,node.rdatasets)

                if GwGroupTemplate.match(GwName):
                    if len(GwName) == 7:
                        Segment = int(GwName[5:])
                    else:
                        Segment = 0    # legacy names -> will be used for onboarding

                    if Segment == 0 or Segment == 99:
                        continue    # >>> Onboarder

                    if Segment not in self.__SegmentDict:
                        print('!! Segment in DNS but not in Git: %s' % (GwName))
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

            print()
            for GwName in sorted(self.__GatewayDict):
                print(GwName.ljust(7),'=',self.__GatewayDict[GwName]['IPs'])

            print()
            for GwIP in sorted(Ip2GwDict):
                print(GwIP,'->',Ip2GwDict[GwIP])

            #----- setting up Segment to GwInstanceNames -----
            print()
            for Segment in sorted(self.__SegmentDict.keys()):
#                print('>>>',Segment,'->',self.__SegmentDict[Segment]['GwIPs'])

                for GwIP in self.__SegmentDict[Segment]['GwIPs']:
                    if GwIP in Ip2GwDict:
                        GwName = Ip2GwDict[GwIP]

                        if GwName not in self.__SegmentDict[Segment]['GwDnsNames']:
                            self.__SegmentDict[Segment]['GwDnsNames'].append(GwName)

#                            if GwName not in self.__SegmentDict[Segment]['GwGitNames'] and Segment > 0 and Segment <= 24:
#                                self.__alert('!! DNS entry without Key in Git: '+GwName+' -> '+str(Segment))

                            if Segment not in self.__GatewayDict[GwName]['DnsSegments']:
                                self.__GatewayDict[GwName]['DnsSegments'].append(Segment)
                            else:
                                self.__alert('!! DNS entries are inconsistent: '+GwName+' -> '+str(Segment))
                    else:
                        self.__alert('!! Unknown Gateway IP: '+GwIP)

                if Segment > 0 and Segment < 25 and len(self.__SegmentDict[Segment]['GwDnsNames']) < 2:
                    self.__alert('!! Too few Gateways in Segment %02d: %s' % (Segment,self.__SegmentDict[Segment]['GwDnsNames']))
                else:
                    print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwDnsNames'])))

            print()
            for GwName in sorted(self.__GatewayDict):
                print(GwName.ljust(7),'->',sorted(self.__GatewayDict[GwName]['DnsSegments']))

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

                    if Segment == 0 or Segment == 99:
                        continue    # >>> Onboarder

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
            with open(os.path.join(BATMAN_DEBUG_FILES,BatmanIF,BATMAN_GATEWAYS), mode='r') as GatewayList:
                BatResult = GatewayList.read().splitlines()
        except:
            print('!! ERROR on Batman GatewayList of',BatmanIF)
            BatResult = None
        else:
            for BatLine in BatResult:
                GwName = None
                GwMAC = BatLine.strip()[:17]

                if GwNewMacTemplate.match(GwMAC):      # e.g. "02:00:38:12:08:06"
                    if int(GwMAC[9:11]) == Segment or GwMAC[9:11] == '61':
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

#                elif MacAdrTemplate.match(GwMAC):
#                    if GwMAC == '00:0d:b9:47:68:bd':    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#                        GwName = 'gw08n02'
#                    else:
#                        self.__alert('!! Invalid Gateway MAC: '+BatmanIF+' -> '+GwMAC)

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
            if len(self.__SegmentDict[Segment]['GwGitNames']) > 0:
                GwList = self.__GetSegmentGwListFromBatman(Segment)
            else:
                GwList = []

            for GwName in GwList:
                if GwName not in self.__GatewayDict:
                    self.__GatewayDict[GwName] = { 'IPs':[], 'DnsSegments':[], 'BatmanSegments':[] }
                    print('++ Inofficial Gateway found:',GwName)

                if Segment not in self.__GatewayDict[GwName]['BatmanSegments']:
                    self.__GatewayDict[GwName]['BatmanSegments'].append(Segment)
#                    print('++ Gateway in Batman but not in DNS:',Segment,GwName)

                if GwName not in self.__SegmentDict[Segment]['GwBatNames']:
                    self.__SegmentDict[Segment]['GwBatNames'].append(GwName)

            for GwName in self.__SegmentDict[Segment]['GwDnsNames']:
                if GwName not in self.__SegmentDict[Segment]['GwBatNames'] and Segment > 0 and Segment < 99:
                    print('!! Gateway in DNS but not in Batman: Seg.%02d -> %s' % (Segment,GwName))

        print()
        for Segment in sorted(self.__SegmentDict):
            print('Seg.%02d -> %s' % (Segment,sorted(self.__SegmentDict[Segment]['GwBatNames'])))

        print()
        for GwName in sorted(self.__GatewayDict):
            print(GwName.ljust(7),'->',sorted(self.__GatewayDict[GwName]['BatmanSegments']))

        print('\n... done.\n')
        return



    #==========================================================================
    # private function "__CheckGatewayDnsServer"
    #
    #
    #--------------------------------------------------------------------------
    def __CheckGatewayDnsServer(self):

        return

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
                        if len(GwName) == 7 and GwName not in GwIgnoreList:
                            InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int(Segment/32), ((Segment-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )
                            InternalGwIPv6 = 'fd21:b4dc:4b%02d::a38:%d' % ( Segment, int(GwName[2:4])*100 + int(GwName[6:8]) )

#                            for DnsServer in [InternalGwIPv4,InternalGwIPv6]:
                            for DnsServer in [InternalGwIPv4]:
                                DnsResolver.nameservers = [DnsServer]

                                for DnsType in ['a','aaaa']:
                                    for i in range(3):
                                        try:
                                            DnsResult = DnsResolver.query(DnsTestTarget,DnsType)
                                        except:
                                            time.sleep(2)
                                            DnsResult = None
                                        else:
                                            break

                                    if DnsResult is None:
#                                        print('!! Error on DNS-Server:',Segment,'->',GwName,'=',DnsServer,'->',DnsTestTarget,'/',DnsType)
                                        self.__alert('!! Error on DNS-Server: Seg.%02d -> %s = %s -> %s / %s' % (Segment,GwName,DnsServer,DnsTestTarget,DnsType) )
#                                        print('!! Error on DNS-Server: Seg.%02d -> %s = %s -> %s / %s' % (Segment,GwName,DnsServer,DnsTestTarget,DnsType) )

        print('... done.\n')
        return



    #=======================================================================
    # private function "__LoadKeysFromGit"
    #
    #   Load and analyse fastd-Keys from Git
    #
    #     self.FastdKeyDict[KeyFileName]   = { 'SegDir','PeerMAC','PeerName','PeerKey' }
    #     self.__Key2FileNameDict[PeerKey] = { 'SegDir','KeyFile' }
    #
    #-----------------------------------------------------------------------
    def __LoadKeysFromGit(self):

        print('Load and analyse fastd-Keys from Git ...')

        KeyFileList = glob(os.path.join(self.__GitPath,'vpn*/peers/*'))

        for KeyFilePath in KeyFileList:
            SegDir   = os.path.dirname(KeyFilePath).split("/")[-2]
            Segment  = int(SegDir[3:])
            FileName = os.path.basename(KeyFilePath)

            if Segment == 0:
                continue    # >>>>>>>>>>>>>>>> no Legacy !!!!!!!!!!!!!!!!!

            if Segment not in self.__SegmentDict:
                self.__SegmentDict[Segment] = { 'GwGitNames':[], 'GwDnsNames':[], 'GwBatNames':[], 'GwIPs':[] }
                print('!! Segment without Gateway:',Segment)

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
                            if not MacAdrTemplate.match(PeerMAC) or PeerMAC.replace(':','') != ffNodeID:
                                self.__alert('!! Invalid MAC in Key File: '+KeyFilePath+' -> '+PeerMAC)
                                PeerMAC = None

                        elif LowerCharLine.startswith('#hostname: '):
                            PeerName = DataLine[11:]

                        elif LowerCharLine.startswith('#segment: '):
                            SegMode = LowerCharLine[10:]

                        elif LowerCharLine.startswith('key '):
                            PeerKey = LowerCharLine.split(' ')[1][1:-2]
                            if not FastdKeyTemplate.match(PeerKey):
                                self.__alert('!! Invalid Key in Key File: '+KeyFilePath+' -> '+PeerKey)
                                PeerKey = None

                        elif not LowerCharLine.startswith('#comment: ') and LowerCharLine != '':
                            self.__alert('!! Invalid Entry in Key File: '+KeyFilePath+' -> '+DataLine)

                    if PeerMAC is not None and PeerKey is not None:
                        if FileName in self.FastdKeyDict or PeerKey in self.__Key2FileNameDict:
                            self.__alert('!! Duplicate Key File: '+FileName+' -> '+SegDir+' / '+self.FastdKeyDict[FileName]['SegDir'])
                            self.__alert('                       '+PeerKey+' = '+self.__Key2FileNameDict[PeerKey]['SegDir']+'/peers/'+self.__Key2FileNameDict[PeerKey]['KeyFile']+' -> '+KeyFilePath)
                            self.AnalyseOnly = True
                        else:
                            self.FastdKeyDict[FileName] = {
                                'SegDir': SegDir,
                                'SegMode': SegMode,
                                'PeerMAC': PeerMAC,
                                'PeerName': PeerName,
                                'PeerKey': PeerKey,
                                'VpnMAC': '',
                                'LastConn': 0,
                                'DnsSeg': None
                            }

                            self.__Key2FileNameDict[PeerKey] = {
                                'SegDir': SegDir,
                                'KeyFile': FileName
                            }

                    else:
                        self.__alert('!! Invalid Key File: '+KeyFilePath)

            else:
                print('++ Invalid Key Filename:', KeyFilePath)

        print('... done: %d\n' % (len(self.FastdKeyDict)))
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

                else:
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
        jsonFastdDict = None
        Retries = 5

        while jsonFastdDict is None and Retries > 0:
            Retries -= 1

            try:
                FastdJsonHTTP = urllib.request.urlopen(URL,timeout=5)
                HttpDate = int(calendar.timegm(time.strptime(FastdJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')))
                StatusAge = int(time.time()) - HttpDate
                jsonFastdDict = json.loads(FastdJsonHTTP.read().decode('utf-8'))
                FastdJsonHTTP.close()
            except:
#                print('** need retry ...')
                jsonFastdDict = None
                time.sleep(2)

        if jsonFastdDict is None:
            print('++ ERROR fastd status connect!',URL)
            return None

        if StatusAge < 900:
            if 'peers' in jsonFastdDict:
                if 'interface' in jsonFastdDict:
                    if int(jsonFastdDict['interface'][3:5]) != Segment:
                        print('!! Bad Interface in fastd status file:',URL,'=',jsonFastdDict['interface'],'->',Segment)
                        return None

                ActiveConnections = self.__AnalyseFastdStatus(jsonFastdDict['peers'],Segment,HttpDate)
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
            if len(self.__GatewayDict[GwName]['BatmanSegments']) > 0 : print()

            if GwName not in GwIgnoreList:
                for ffSeg in sorted(self.__GatewayDict[GwName]['BatmanSegments']):
                    if ffSeg > 0:
                        InternalGwIPv4 = '10.%d.%d.%d' % ( 190+int(ffSeg/32), ((ffSeg-1)*8)%256, int(GwName[2:4])*10 + int(GwName[6:8]) )

                        #----- MTU 1312 -----
                        if GwName[:6] == 'gw05n0' or GwName == 'gw04n02':
                            FastdJsonURL = 'http://%s/data/vpn%02dmtv.json' % (InternalGwIPv4,ffSeg)
                        else:
                            FastdJsonURL = 'http://%s/data/vpy%02d.json' % (InternalGwIPv4,ffSeg)

                        ActiveConnections = self.__LoadFastdStatusFile(FastdJsonURL,ffSeg)
                        if ActiveConnections is not None:
                            print('... %ss%02d = %d' % (GwName,ffSeg,ActiveConnections))

                        #----- MTU 1406 -----
                        FastdJsonURL = 'http://%s/data/vpn%02d.json' % (InternalGwIPv4,ffSeg)
#                        InternalGwIPv6 = 'fd21:b4dc:4b%02d::a38:%d' % ( ffSeg, int(GwName[2:4])*100 + int(GwName[6:8]) )
#                        FastdJsonURL = 'http://[%s]/data/vpn%02d.json' % (InternalGwIPv6,ffSeg)

                        ActiveConnections = self.__LoadFastdStatusFile(FastdJsonURL,ffSeg)
                        if ActiveConnections is not None and ActiveConnections != 0:
                            print('... %ss%02d (MTU 1406) = %d' % (GwName,ffSeg,ActiveConnections))

            else:
                print('\n...',GwName,'... ignored.')

        print('\n... done.')
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

                elif DnsPeerID != '@' and DnsPeerID != '*':
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
                (self.FastdKeyDict[PeerFileName]['DnsSeg'] != self.FastdKeyDict[PeerFileName]['SegDir'])):

                self.__alert('!! DNS Entry missing or wrong: '+PeerFileName+' -> '+self.FastdKeyDict[PeerFileName]['PeerMAC']+' = '+self.FastdKeyDict[PeerFileName]['PeerName'])

                if DnsUpdate is None:
                    DnsKeyRing = dns.tsigkeyring.from_text( {self.__DnsAccDict['ID'] : self.__DnsAccDict['Key']} )
                    DnsUpdate  = dns.update.Update(SegAssignDomain, keyring = DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')

                if DnsUpdate is not None:
                    PeerDnsName = PeerFileName+'-'+self.FastdKeyDict[PeerFileName]['PeerKey'][:12]
                    PeerDnsIPv6 = '%s%d' % (SegAssignIPv6Prefix,int(self.FastdKeyDict[PeerFileName]['SegDir'][3:]))

                    if self.FastdKeyDict[PeerFileName]['DnsSeg'] is None:
                        DnsUpdate.add(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)
                        print('>>> Adding Peer to DNS:',PeerDnsName,'->',PeerDnsIPv6)
                    else:
                        DnsUpdate.replace(PeerDnsName, 120, 'AAAA',PeerDnsIPv6)
                        print('>>> Updating Peer in DNS:',PeerDnsName,'->',PeerDnsIPv6)

                else:
                    self.__alert('!! ERROR on updating DNS: '+PeerDnsName+' -> '+PeerDnsIPv6)

                isOK = False

        if DnsUpdate is not None:
            dns.query.tcp(DnsUpdate,self.__DnsServerIP)
            print('... Update launched on DNS-Server',self.__DnsServerIP)

        return isOK



    #=========================================================================
    # Method "CheckNodesInSegassignDNS"
    #
    #   Returns True if everything is OK
    #
    #=========================================================================
    def CheckNodesInSegassignDNS(self):

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

        SegmentList = []

        for Segment in self.__SegmentDict.keys():
            if len(self.__SegmentDict[Segment]['GwBatNames']) > 0:
                SegmentList.append(Segment)

        return SegmentList



    #==============================================================================
    # Method "MoveNodes"
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

#                        print(SourceFile,'->',DestFile)
                        print('%s = %s: %s -> vpn%02d' % (KeyFileName,self.FastdKeyDict[KeyFileName]['PeerName'],self.FastdKeyDict[KeyFileName]['SegDir'],NodeMoveDict[ffNodeMAC]))

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

#                            self.__alert('   '+SourceFile+' -> '+DestFile)
                            self.__alert('   %s = %s: %s -> vpn%02d' % (KeyFileName,self.FastdKeyDict[KeyFileName]['PeerName'],self.FastdKeyDict[KeyFileName]['SegDir'],NodeMoveDict[ffNodeMAC]))

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
