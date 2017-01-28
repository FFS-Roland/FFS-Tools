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
import urllib.request
import time
import datetime
import json
import re
import fcntl
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

SegAssignDomain   = 'segassign.freifunk-stuttgart.de'

DnsSegTemplate    = re.compile('^2001:2:0:711::[0-9][0-9]?$')
DnsNodeTemplate   = re.compile('^ffs-[0-9a-f]{12}-[0-9a-f]{12}$')

GwNameTemplate    = re.compile('^gw[01][0-9]{1,2}')
GwAllMacTemplate  = re.compile('^02:00:((0a)|(3[5-9]))(:[0-9a-f]{2}){3}')
GwNewMacTemplate  = re.compile('^02:00:(3[5-9])(:[0-9a-f]{2}){3}')

MacAdrTemplate    = re.compile('^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
NodeIdTemplate    = re.compile('^[0-9a-f]{12}$')

PeerTemplate      = re.compile('^ffs-[0-9a-f]{12}')
PeerTemplate1     = re.compile('^ffs[-_][0-9a-f]{12}')
PeerTemplate2     = re.compile('^ffs[0-9a-f]{12}')

SegmentTemplate   = re.compile('^[0-9]{2}$')

KeyDirTemplate    = re.compile('^vpn[0-9]{2}$')
FastdKeyTemplate  = re.compile('^[0-9a-f]{64}$')




class ffGatewayInfo:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,GitPath):

        # public Attributes
        self.FastdKeyDict = {}          # FastdKeyDic[KeyFileName]  -> SegDir, VpnMAC, PeerMAC, PeerName, PeerKey
        self.Alerts       = []          # List of  Alert-Messages
        self.AnalyseOnly  = False       # Blocking active Actions due to inconsistent Data

        # private Attributes
        self.__GitPath = GitPath

        self.__Key2FileNameDict = {}    # Key2FileNameDict[PeerKey] -> SegDir, KeyFileName
        self.__SegmentList = []

        # Initializations
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



    #-----------------------------------------------------------------------
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
                self.__SegmentList.append(int(SegDir[3:]))
                VpnPeerPath = os.path.join(SegPath,'peers')

                for KeyFileName in os.listdir(VpnPeerPath):
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
    def __AnalyseFastdStatus(self,FastdPeersDict,Segment):

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

                    else:
                        print('!! PeerKey not in FastdKeyDict:',FastdPeersDict[PeerKey]['name'],'=',PeerKey)
                        print()

                elif PeerTemplate1.match(FastdPeersDict[PeerKey]['name']):
                    print('!! PeerKey not in Git:',FastdPeersDict[PeerKey]['name'],'=',PeerKey)
                    print()

#        print('... Active Keys =',ActiveKeyCount)
        return



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

        try:
            FastdJsonHTTP = urllib.request.urlopen(URL)
            HttpDate = datetime.datetime.strptime(FastdJsonHTTP.info()['Last-Modified'][5:],'%d %b %Y %X %Z')
            StatusAge = datetime.datetime.utcnow() - HttpDate
            jsonFastdDict = json.loads(FastdJsonHTTP.read().decode('utf-8'))
            FastdJsonHTTP.close()
        except:
    #        print('++ ERROR fastd status connect!',FastdJsonURL)
            return
        else:
            print('Load and analyse',URL,'...')

            StatusAge = datetime.datetime.utcnow() - HttpDate

            if StatusAge.total_seconds() < 900:
                if 'peers' in jsonFastdDict:
                    if 'interface' in jsonFastdDict:
                        if int(jsonFastdDict['interface'][3:5]) != Segment:
                            print('!! ERROR: Bad Interface in fastd status file:',jsonFastdDict['interface'],'->',Segment)
                            return

                    self.__AnalyseFastdStatus(jsonFastdDict['peers'],Segment)
#                    print()
                else:
                    print('!! ERROR: Bad fastd status file!')
            else:
                print('++ ERROR fastd status to old!')

        return



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
        print('Loading fastd Status Infos ...')

        for ffGW in [1, 5, 6, 8]:
            print('... GW%02d ...' % (ffGW))

            for GwInstance in range(0,8):
                for ffSeg in self.__SegmentList:

                    FastdJsonURL = 'http://gw%02dn%02d.freifunk-stuttgart.de/data/vpn%02d.json' % (ffGW,GwInstance,ffSeg)
                    self.__LoadFastdStatusFile(FastdJsonURL,ffSeg)

                    if ffGW == 5:
                        FastdJsonURL = 'http://gw%02dn%02d.freifunk-stuttgart.de/data/vpn%02dip6.json' % (ffGW,GwInstance,ffSeg)
                        self.__LoadFastdStatusFile(FastdJsonURL,ffSeg)

        self.__LoadFastdStatusFile('http://gw09.freifunk-stuttgart.de/fastd/ffs.status.json',0)

        print('... done.')
        print('-------------------------------------------------------')
        return



    #=========================================================================
    # Method "VerifyDNS"
    #
    #   Returns True if everything is OK
    #
    #=========================================================================
    def VerifyDNS(self,DnsAccountDict):

        print('\nLoading DNS Zone for checking ...')

        isOK = True

        try:
            DnsResolver = dns.resolver.Resolver()
            DnsServerIP = DnsResolver.query('%s.' % (DnsAccountDict['Server']),'a')[0].to_text()
            DnsZone     = dns.zone.from_xfr(dns.query.xfr(DnsServerIP,SegAssignDomain))
        except:
            self.__alert('!! ERROR on fetching DNS Zone!')
            self.AnalyseOnly = True
            isOK = False

        if isOK:
            #---------- Check DNS against Git ----------
            print('Checking DNS Entries against Keys in Git ...')
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
                                    SegFromDNS = 'vpn'+IPv6[14:].zfill(2)
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

            for PeerFileName in self.FastdKeyDict:
                if ((PeerTemplate.match(PeerFileName)) and
                    (self.FastdKeyDict[PeerFileName]['PeerKey'] != '') and
                    (self.FastdKeyDict[PeerFileName]['SegDir'] != 'vpn00') and
                    (self.FastdKeyDict[PeerFileName]['DnsSeg'] is None)):

                    print('++ DNS Entry missing:',PeerFileName,'->',self.FastdKeyDict[PeerFileName]['PeerMAC'],'=',self.FastdKeyDict[PeerFileName]['PeerName'].encode('utf-8'))
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
        return self.__SegmentList



    #=========================================================================
    # Method "FastdKeys"
    #
    #   Returns Dictionary of Fastd Keys with Filename and MACs
    #
    #=========================================================================
    def FastdKeys(self):
        return self.FastdKeyDict



    #=========================================================================
    # Method "WriteKeyData"
    #
    #   Writes Fastd Keys as json file with Fastd Key <-> MACC
    #
    #=========================================================================
    def WriteKeyData(self,Path):

        print('Creating Fastd Key Database ...')

        KeyDataDict = { 'Key2Mac':{},'Mac2Key':{} }

        for KeyFileName in self.FastdKeyDict:
            if self.FastdKeyDict[KeyFileName]['PeerKey'] != '':
                KeyDataDict['Key2Mac'][self.FastdKeyDict[KeyFileName]['PeerKey'][:12]] = {
                    'SegDir':self.FastdKeyDict[KeyFileName]['SegDir'],
                    'KeyFile':KeyFileName,
                    'PeerMAC':self.FastdKeyDict[KeyFileName]['PeerMAC']
                }

            if self.FastdKeyDict[KeyFileName]['PeerMAC'] != '':
                KeyDataDict['Mac2Key'][self.FastdKeyDict[KeyFileName]['PeerMAC']] = {
                    'SegDir':self.FastdKeyDict[KeyFileName]['SegDir'],
                    'KeyFile':KeyFileName,
                    'PeerKey':self.FastdKeyDict[KeyFileName]['PeerKey'][:12]
                }

        try:
            LockFile = open('/tmp/.ffsKeyData.lock', mode='w+')
            fcntl.lockf(LockFile,fcntl.LOCK_EX)
            print('Writing Fastd Key Database as json-File ...')

            KeyJsonFile = open(os.path.join(Path,'KeyData.json'), mode='w')
            json.dump(KeyDataDict,KeyJsonFile)
            KeyJsonFile.close()

        except:
            print('\n!! Error on Writing Fastd Key Database as json-File!\n')

        finally:
            fcntl.lockf(LockFile,fcntl.LOCK_UN)
            LockFile.close()

        print('... done.\n')
        return
