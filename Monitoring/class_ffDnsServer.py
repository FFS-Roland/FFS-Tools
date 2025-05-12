#!/usr/bin/python3

#################################################################################################
#                                                                                               #
#   class_ffDnsServer.py                                                                        #
#                                                                                               #
#   Access DNS-Server for Queries, Updates etc.                                                 #
#                                                                                               #
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
import re

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
DnsCacheTime = 120



class ffDnsServer:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self, ffDomain, DnsAccDict):

        # public Attributes
        self.Alerts         = []           # List of  Alert-Messages
        self.ReadOnly       = True         # Blocking write / update Actions

        # private Attributes
        self.__DnsAccDict   = DnsAccDict   # DNS Account
        self.__ffDomain     = ffDomain     # DNS-Domain

        self.__DnsServer    = {'primary': None, 'secondary': []}
        self.__DnsKeyRing   = None
        self.__DnsUpdate    = None

        # Initializations
        self.__GetDnsServer()

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


    #--------------------------------------------------------------------------
    # private function "__GetDnsServer"
    #
    #   Get primary DNS-Server-IP for Domain, secondary as Fallback
    #
    #--------------------------------------------------------------------------
    def __GetDnsServer(self):

        resolver = dns.resolver.Resolver()
        ServerIP = None

        try:
            ServerName = resolver.resolve(self.__ffDomain, 'SOA')[0].to_text().split()[0]
            ServerIP = resolver.resolve(ServerName, 'A')[0].to_text()
        except:
            self.__DnsServer['primary'] = None
            self.__alert('++ ERROR: No SOA Entry for \"%s\" !' % (self.__ffDomain))
        else:
            self.__DnsServer['primary'] = ServerIP
            self.ReadOnly = False

        try:
            for DnsRecord in resolver.resolve('%s.'%(self.__ffDomain),'NS'):
                ServerName = DnsRecord.to_text()
                ServerIP = resolver.resolve(ServerName, 'A')[0].to_text()
#                print(ServerName, '=', ServerIP)

                if (self.__DnsServer['primary'] == None or ServerIP != self.__DnsServer['primary']) and ServerIP not in self.__DnsServer['secondary']:
                    self.__DnsServer['secondary'].append(ServerIP)
        except:
            print('++ ERROR on accessing NS-Entries for \"%s\" !' % (self.__ffDomain))

        try:
            self.__DnsKeyRing = dns.tsigkeyring.from_text( {self.__DnsAccDict['ID'] : self.__DnsAccDict['Key']} )

            if self.__DnsServer['primary'] is not None:
                self.__DnsUpdate  = dns.update.Update(self.__ffDomain, keyring = self.__DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')
        except:
            self.__DnsKeyRing = None
            self.__DnsUpdate  = None

        return


    #--------------------------------------------------------------------------
    # private function "__GetIpFromCNAME"
    #
    #    Returns IpList
    #
    #--------------------------------------------------------------------------
    def __GetIpFromCNAME(self, DnsName):

        DnsResolver = None
        IpList = []

        try:
            DnsResolver = dns.resolver.Resolver()
        except:
            DnsResolver = None

        if DnsResolver is not None:
            for DnsType in ['A', 'AAAA']:
                try:
                    DnsResult = DnsResolver.query(DnsName, DnsType)
                except:
                    DnsResult = None

                if DnsResult is not None:
                    for DnsIP in DnsResult:
#                        print('>>> GwIP:', DnsIP)  #................................................
                        IpList.append(DnsIP.to_text())

            try:
                DnsResult = DnsResolver.query(DnsName,'CNAME')
            except:
                DnsResult = None

            if DnsResult is not None:
                for Cname in DnsResult:
                    sName = Cname.to_text()
#                    print('>>> Cname: %s' % (sName))  #................................................
                    IpList.append(self.__GetIpFromCNAME(sName))

        return IpList


    #--------------------------------------------------------------------------
    # private function "__GetIpFromDnsZone
    #
    #
    #--------------------------------------------------------------------------
    def __GetIpFromDnsZone(self, DnsZone):

        dicZoneIPs = {}

        for name, node in DnsZone.nodes.items():
            for rds in node.rdatasets:
                sDnsName = name.to_text()

                if sDnsName not in dicZoneIPs:
                    dicZoneIPs[sDnsName] = []

                if rds.rdtype == dns.rdatatype.A or rds.rdtype == dns.rdatatype.AAAA:
                    for IpRecord in rds:
                        IpAddress = IpRecord.to_text()

                        if IpAddress not in dicZoneIPs[sDnsName]:
                            dicZoneIPs[sDnsName].append(IpAddress)

                elif rds.rdtype == dns.rdatatype.CNAME:
                    for CnRecord in rds:
                        Cname = CnRecord.to_text()

                        if Cname[-1] != '.':
                            Cname += '.' + self.__ffDomain

                        IpList = self.__GetIpFromCNAME(Cname)

                        for IpAddress in IpList:
                            if IpAddress not in dicZoneIPs[sDnsName]:
                                dicZoneIPs[sDnsName].append(IpAddress)

                if dicZoneIPs[sDnsName] == []:
                    del dicZoneIPs[sDnsName]

        return dicZoneIPs


    #==============================================================================
    # public function "GetDnsZone"
    #
    #    Returns List of DNS-Entries
    #
    #==============================================================================
    def GetDnsZone(self):

        DnsZone = None

        if self.__DnsServer['primary'] is not None and self.__DnsKeyRing is not None:
            print('Loading DNS Zone \"%s\" from Primary \"%s\" ...' % (self.__ffDomain, self.__DnsServer['primary']))

            try:
                DnsResolver = dns.resolver.Resolver()
                DnsZone     = dns.zone.from_xfr( dns.query.xfr(self.__DnsServer['primary'], self.__ffDomain, keyring = self.__DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512') )
            except:
                self.__alert('!! ERROR on fetching DNS Zone \"%s\" from Primary \"%s\".' % (self.__ffDomain, self.__DnsServer['primary']))
                DnsZone = None

        if DnsZone is None:
            self.ReadOnly = True

            for DnsServerIP in self.__DnsServer['secondary']:
                print('Loading DNS Zone \"%s\" from Secondary \"%s\" ...' % (self.__ffDomain, DnsServerIP))

                try:
                    DnsResolver = dns.resolver.Resolver()
                    DnsZone     = dns.zone.from_xfr( dns.query.xfr(DnsServerIP, self.__ffDomain, keyring = self.__DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512') )
                except:
                    self.__alert('!! ERROR on fetching DNS Zone \"%s\" from Secondary \"%s\".' % (self.__ffDomain, DnsServerIP))
                    DnsZone = None
                else:
                    break

        if DnsZone is not None:
            dicZoneIPs = self.__GetIpFromDnsZone(DnsZone)
        else:
            dicZoneIPs = None

        return dicZoneIPs


    #==============================================================================
    # public function "AddEntry"
    #
    #    Add DNS-Entry
    #
    #==============================================================================
    def AddEntry(self, sName, sIP):

        if self.__DnsUpdate is not None:
            if ':' in sIP:
                self.__DnsUpdate.add(sName, DnsCacheTime, 'AAAA', sIP)
            else:
                self.__DnsUpdate.add(sName, DnsCacheTime, 'A', sIP)

            print('>>> Adding DNS-Entry: %s -> %s' % (sName, sIP))
        return


    #==============================================================================
    # public function "DelEntry"
    #
    #    Delete DNS-Entry
    #
    #==============================================================================
    def DelEntry(self, sName, sIP):

        if self.__DnsUpdate is not None:
            if sIP is None:
                self.__DnsUpdate.delete(sName)
                print('>>> Deleting DNS-Name with all IPs: %s' % (sName))
            else:
                if ':' in sIP:
                    self.__DnsUpdate.delete(sName, 'AAAA', sIP)
                else:
                    self.__DnsUpdate.delete(sName, 'A', sIP)

                print('>>> Deleting DNS-Entry: %s -> %s' % (sName, sIP))
        return


    #==============================================================================
    # public function "ReplaceEntry"
    #
    #    Replace DNS-Entry
    #
    #==============================================================================
    def ReplaceEntry(self, sName, sIP):

        if self.__DnsUpdate is not None:
            if ':' in sIP:
                self.__DnsUpdate.replace(sName, DnsCacheTime, 'AAAA', sIP)
            else:
                self.__DnsUpdate.replace(sName, DnsCacheTime, 'A', sIP)

            print('>>> Replacing IP of DNS-Entry: %s -> %s' % (sName, sIP))
        return


    #==============================================================================
    # public function "CommitChanges"
    #
    #    Commit DNS-Update
    #
    #==============================================================================
    def CommitChanges(self):

        isOK = False

        if self.__DnsUpdate is not None:
            if len(self.__DnsUpdate.index) > 1:
                print('>> %d DNS-Changes are pending ...' % (len(self.__DnsUpdate.index)-1))

                try:
                    result = dns.query.tcp(self.__DnsUpdate, self.__DnsServer['primary'])
                except:
                    result = None

                if result is not None and 'rcode NOERROR' in result.to_text():
                    print('... DNS-Update launched successfully.')
                    isOK = True
                else:
                    self.__alert('*** ERROR on DNS Update, Server = \"%s\" !!' % (self.__DnsServer['primary']))
            else:
                print('... No DNS-Changes are pending.')
                isOK = True

            self.__DnsUpdate  = dns.update.Update(self.__ffDomain, keyring = self.__DnsKeyRing, keyname = self.__DnsAccDict['ID'], keyalgorithm = 'hmac-sha512')
        else:
            print('*** No DNS-Server for updates available !!')

        return isOK
