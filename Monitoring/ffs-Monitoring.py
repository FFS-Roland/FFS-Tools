#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  ffs-Monitoring.py                                                                      #
#                                                                                         #
#  Segment-Assignment of Nodes is monitored and corrected automatically if neccessary.    #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#       --gitrepo  = Git Repository with fastd KeyFiles                                   #
#       --data     = Path to Databases                                                    #
#       --logs     = Path to LogFiles                                                     #
#                                                                                         #
#  Needed json-Files from Webservers:                                                     #
#                                                                                         #
#       raw.json (Yanic)     -> Node Names and Information from Yanic                     #
#       raw.json (Hopglass)  -> Node Names and Information from Hopglass-Server           #
#       vpyXX.json           -> fastd Status-Files from Gateways                          #
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
import time
import datetime
import argparse
import smtplib

from email.mime.text import MIMEText

from class_ffGatewayInfo import *
from class_ffNodeInfo import *
from class_ffMeshNet import *




#=============================================================
# Local File Names
#=============================================================

AccountsFileName  = '.Accounts.json'
NodeDictFileName  = 'NodeDict.json'

MacTableFile      = 'MacTable.lst'
MeshCloudListFile = 'MeshClouds.lst'




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
#            Email['Bcc']     = Account['MailBCC']

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
parser.add_argument('--data', dest='DATAPATH', action='store', required=True, help='Path to Databases')
parser.add_argument('--logs', dest='LOGPATH', action='store', required=True, help='Path to LogFiles')
args = parser.parse_args()

AccountsDict = __LoadAccounts(os.path.join(args.DATAPATH,AccountsFileName))  # All needed Accounts for Accessing resricted Data

if AccountsDict is None:
    print('!! FATAL ERROR: Accounts not available!')
    exit(1)



print('====================================================================================\n\nSetting up Gateway Data ...\n')
ffsGWs = ffGatewayInfo(args.GITREPO,AccountsDict['DNS'])


print('====================================================================================\n\nSetting up Node Data ...\n')
ffsNodes = ffNodeInfo(AccountsDict,args.GITREPO,args.DATAPATH)

ffsNodes.GetBatmanNodeMACs(ffsGWs.GetSegmentList())
ffsNodes.AddFastdInfos(ffsGWs.FastdKeyDict)
ffsNodes.DumpMacTable(os.path.join(args.LOGPATH,MacTableFile))

if not ffsNodes.SetDesiredSegments():
    print('!! FATAL ERROR: Regions / Segments not available!')
    exit(1)


print('====================================================================================\n\nSetting up Mesh Net Info ...\n')

ffsNet = ffMeshNet(ffsNodes,ffsGWs)    # Find Mesh-Clouds with analysing for shortcuts

ffsNet.WriteMeshCloudList(os.path.join(args.LOGPATH,MeshCloudListFile))


#---------- Actions ----------
NodeMoveDict = ffsNet.GetMoveDict()
MailBody = ''

if NodeMoveDict is None:
    ffsNodes.CheckNodesInNodesDNS(AccountsDict['DNS'])

    if not ffsNodes.AnalyseOnly and not ffsGWs.AnalyseOnly and not ffsNet.AnalyseOnly:
        ffsNodes.WriteNodeDict()
    else:
        print('\n!!! Analyse only: Nodes = %s, GWs = %s, Net = %s\n' % (ffsNodes.AnalyseOnly,ffsGWs.AnalyseOnly,ffsNet.AnalyseOnly))
else:
    print('\nMoving Nodes ...')

    if ffsNodes.AnalyseOnly or ffsGWs.AnalyseOnly or ffsNet.AnalyseOnly:
        MailBody = '!! There are Nodes to be moved but cannot due to inconsistent Data !!\n'
    else:
        ffsGWs.MoveNodes(NodeMoveDict,AccountsDict['Git'])
        ffsNodes.WriteNodeDict()

print('\nChecking for Alerts ...')

for Alert in ffsGWs.Alerts:
    MailBody += Alert+'\n'

for Alert in ffsNodes.Alerts:
    MailBody += Alert+'\n'

for Alert in ffsNet.Alerts:
    MailBody += Alert+'\n'

if MailBody != '':
    print('\nSending Email to inform Admins on Errors ...')
    __SendEmail('Alert from ffs-Monitor \"%s\"' % (socket.gethostname()),MailBody,AccountsDict['StatusMail'])
else:
    TimeInfo = datetime.datetime.now()
    if TimeInfo.hour == 12 and TimeInfo.minute < 9:
        print('\nSending Hello Mail to inform Admins beeing alive ...')
        __SendEmail('Hello from ffs-Monitor \"%s\"' % (socket.gethostname()),'ffs-Monitor is alive. No Alerts right now.',AccountsDict['StatusMail'])

print('\nOK.\n')
