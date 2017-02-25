#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  ffs-Monitoring.py                                                                      #
#                                                                                         #
#  Segment-Assignment of Nodes is monitored and corrected automatically if neccessary.    #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#       --gitrepo  = Git Repository with KeyFiles                                         #
#       --logs     = Path to LogFiles                                                     #
#       --json     = Path to json-Files (Databases with fastd-Keys and Statistics)        #
#                                                                                         #
#  Needed json-Files from Webserver:                                                      #
#                                                                                         #
#       raw.json             -> Node Names and Information                                #
#       nodesdb.json         -> Region = Segment                                          #
#       alfred-json-158.json -> Nodeinfos                                                 #
#       alfred-json-159.json -> VPN-Uplinks                                               #
#       alfred-json-160.json -> Neighbors                                                 #
#       fastd-clean.json     -> fastd-Keys (live Data)                                    #
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
import time
import datetime
import argparse
import smtplib

from email.mime.text import MIMEText

from class_ffGatewayInfo import *
from class_ffNodeInfo import *
from class_ffMeshNet import *




#-------------------------------------------------------------
# Local File Names
#-------------------------------------------------------------

AccountsFileName  = '.Accounts.json'

MacTableFile      = 'MacTable.lst'
MeshCloudListFile = 'MeshClouds.lst'
NodeMoveFile      = 'NodeMoves.lst'


#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

AlfredURL         = 'http://netinfo.freifunk-stuttgart.de/json/'




#-----------------------------------------------------------------------
# Function "__LoadAccounts"
#
#   Load Accounts from Accounts.json into AccountsDict
#
#-----------------------------------------------------------------------
def __LoadAccounts(AccountFile):

    try:
        AccountJsonFile = open(AccountFile, mode='r')
        AccountsDict = json.load(AccountJsonFile)
        AccountJsonFile.close()

    except:
        print('\n!! Error on Reading Accounts json-File!\n')
        AccountsDict = None

    return AccountsDict



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
            print('\nEmail was sent to',Account['MailTo'])

        except:
            print('!! ERROR on sending Email to',Account['MailTo'])

    return



#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
parser = argparse.ArgumentParser(description='Check Freifunk Segments')
parser.add_argument('--gitrepo', dest='GITREPO', action='store', required=True, help='Git Repository with KeyFiles')
parser.add_argument('--logs', dest='LOGPATH', action='store', required=True, help='Path to LogFiles')
parser.add_argument('--json', dest='JSONPATH', action='store', required=False, help='optional Path to KeyDatabase')
args = parser.parse_args()

AccountsDict = __LoadAccounts(os.path.join(args.JSONPATH,AccountsFileName))  # All needed Accounts for Accessing resricted Data

if AccountsDict is None:
    print('!! FATAL ERROR: Accounts not available!')
    exit(1)


#---------- Gateways ----------
print('Setting up Gateway Data ...')
ffsGWs = ffGatewayInfo(args.GITREPO,AccountsDict['DNS'])

isOK = ffsGWs.CheckNodesInDNS()    # Check DNS entries of Nodes against keys from Git

if not args.JSONPATH is None:
    print('Writing Fastd Key Database ...')
    ffsGWs.WriteKeyData(args.JSONPATH)


#---------- Nodes ----------
print('Setting up Node Data ...')
ffsNodes = ffNodeInfo(AlfredURL,AccountsDict['raw.json'])

ffsNodes.DumpMacTable(os.path.join(args.LOGPATH,MacTableFile))


#---------- FF-Network ----------
print('Setting up Mesh Net Info and Checking Segments ...')

ffsNet = ffMeshNet(ffsNodes,ffsGWs)

ffsNet.MergeData(args.JSONPATH)    # Merge Data from Gateways to NodeInfos and check consistency

ffsNet.UpdateStatistikDB(args.JSONPATH)

ffsNet.CheckSegments()    # Find Mesh-Clouds with anasysing for shortcuts


print('\nWriting Logs ...')

ffsNet.WriteMeshCloudList(os.path.join(args.LOGPATH,MeshCloudListFile))
ffsNet.WriteMoveList(os.path.join(args.LOGPATH,NodeMoveFile))



print('\nChecking for Alerts ...')

MailBody = ''

for Alert in ffsGWs.Alerts:
    MailBody += Alert+'\n'

for Alert in ffsNodes.Alerts:
    MailBody += Alert+'\n'

for Alert in ffsNet.Alerts:
    MailBody += Alert+'\n'

if MailBody != '':
    print('\nSending Email to inform Admins on Errors ...')
    __SendEmail('Alert from ffs-Monitor',MailBody,AccountsDict['SMTP'])
else:
    TimeInfo = datetime.datetime.now()
    if TimeInfo.hour == 12 and TimeInfo.minute < 5:
        print('\nSending Hello Mail to inform Admins beeing alive ...')
        __SendEmail('Hello from ffs-Monitor','ffs-Monitor is alive. No Alerts right now.',AccountsDict['SMTP'])

print('\nOK.\n')
