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

import os
import time
import datetime
import argparse
import smtplib

from email.mime.text import MIMEText

from class_ffGatewayInfo import *
from class_ffNodeInfo import *
from class_ffMeshNet import *
from class_ffLocation import *




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
            Email['Bcc']     = Account['MailBCC']

            server = smtplib.SMTP(host=Account['Server'],port=Account['Port'],timeout=5)

            if (Account['Password'] != ''):
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

AccountsDict = __LoadAccounts(os.path.join(args.DATAPATH, AccountsFileName))  # All needed Accounts for Accessing resricted Data

if AccountsDict is None:
    print('!! FATAL ERROR: Accounts not available!')
    exit(1)



print('====================================================================================\n\nSetting up Gateway Data ...\n')
ffsGWs = ffGatewayInfo(args.GITREPO, AccountsDict['DNS'])

ffsGWs.CheckGatewayDnsServer()
ffsGWs.CheckGatewayDhcpServer()
ffsGWs.CheckGatewayInternet()

GwSegmentList = ffsGWs.GetSegmentList()
GwUplinkInfos = ffsGWs.GetNodeUplinkInfos()


print('====================================================================================\n\nSetting up Node Data ...\n')
ffsNodes = ffNodeInfo(AccountsDict, args.GITREPO, args.DATAPATH)

ffsNodes.AddUplinkInfos(GwUplinkInfos)
ffsNodes.DumpMacTable(os.path.join(args.LOGPATH, MacTableFile))


print('====================================================================================\n\nSetting up Location Data ...\n')
ffsLocationInfo = ffLocation(args.GITREPO, args.DATAPATH)

if not ffsNodes.SetDesiredSegments(ffsLocationInfo):
    print('!! FATAL ERROR: Regions / Segments not available!')
    exit(1)

ffsNodes.CheckConsistency(GwSegmentList)


print('====================================================================================\n\nSetting up Mesh Net Info ...\n')
ffsNet = ffMeshNet(ffsNodes)

ffsNet.CreateMeshCloudList()
ffsNet.CheckMeshClouds()
ffsNet.CheckSingleNodes()

ffsNet.WriteMeshCloudList(os.path.join(args.LOGPATH, MeshCloudListFile))


#---------- Actions ----------
NodeMoveDict = ffsNet.GetMoveDict()
MailBody = ''

if NodeMoveDict is None:
    ffsNodes.CheckNodesInDNS()

    if not ffsNodes.AnalyseOnly and not ffsGWs.AnalyseOnly and not ffsNet.AnalyseOnly:
        ffsNodes.WriteNodeDict()
    else:
        print('\n!!! Analyse only: Nodes = %s, GWs = %s, Net = %s\n' % (ffsNodes.AnalyseOnly, ffsGWs.AnalyseOnly, ffsNet.AnalyseOnly))
else:
    print('\nMoving Nodes ...')

    if ffsNodes.AnalyseOnly or ffsGWs.AnalyseOnly or ffsNet.AnalyseOnly:
        MailBody = '!! There are Nodes to be moved but cannot due to inconsistent Data !!\n'
    else:
        ffsGWs.MoveNodes(NodeMoveDict, AccountsDict['Git'])
        ffsNodes.WriteNodeDict()

print('\nChecking for Alerts ...')

for Alert in ffsGWs.Alerts:
    MailBody += Alert+'\n'

for Alert in ffsNodes.Alerts:
    MailBody += Alert+'\n'

for Alert in ffsNet.Alerts:
    MailBody += Alert+'\n'

TimeInfo = datetime.datetime.now()
TimeString = TimeInfo.strftime('%d.%m.%Y - %H:%M:%S')

if MailBody != '':
    print('\nSending Email to inform Admins on Errors ...')
    __SendEmail('Alert from ffs-Monitor \"%s\"' % (socket.gethostname()), TimeString+'\n\n'+MailBody, AccountsDict['StatusMail'])
else:
    if TimeInfo.hour == 12 and TimeInfo.minute < 12:
        print('\nSending Hello Mail to inform Admins beeing alive ...')
        __SendEmail('Hello from ffs-Monitor \"%s\"' % (socket.gethostname()), TimeString+'\n\nffs-Monitor is alive. No Alerts right now.', AccountsDict['StatusMail'])

print('\nOK.\n')
