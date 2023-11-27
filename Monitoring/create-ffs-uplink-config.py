#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  create-ffs-uplink-config.py                                                            #
#                                                                                         #
#  Creating configuration files for fastd and network to be used as uplink to FFS.        #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#    --monid    = ID of FFS-Monitor                                                       #
#    --siteconf = Path to "site.conf"                                                     #
#    --vpnkeys  = Path to folder with own fastd-key-files                                 #
#    --gitpeers = Git Repo with peers                                                     #
#                                                                                         #
###########################################################################################

import os
import subprocess
import re
import argparse
from glob import glob



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------

GwTemplate = re.compile('^gw[0-9]{2} ')



#-----------------------------------------------------------------------
# Function "GetWanInterface"
#
#   Get Name of WAN-Interface
#
#-----------------------------------------------------------------------
def GetWanInterface():

    WanInterface = None

    try:
        RouteCmd = subprocess.run(['/bin/ip','r'], stdout=subprocess.PIPE)
        RouteResult = RouteCmd.stdout.decode('utf-8')
    except:
        print('!! Cannot get default route!')
    else:
        for RouteLine in RouteResult.split('\n'):
            if len(RouteLine.strip()) > 0:
                RouteInfo = RouteLine.split()

                if RouteInfo[0] == 'default' and RouteInfo[1] == 'via' and RouteInfo[3] == 'dev':
                    WanInterface = RouteInfo[4]
                    break

    return WanInterface



#-----------------------------------------------------------------------
# Function "LoadGwKeys"
#
#   Extract fastd-keys of gateways from site.conf
#
#   Parameter:
#   > SiteConfPath = Path to site.conf
#
#   return:
#     GwKeyDict { <GW> : Key }
#
#-----------------------------------------------------------------------
def LoadGwKeys(SiteConfPath):

    print('Loading GW-Keys from site.conf ...')
    GwKeyDict = {}

    with open(SiteConfPath,'r') as SiteConfFile:
        SiteData = SiteConfFile.read()

        State = 0
        GwGroup = None

        for FileLine in SiteData.split('\n'):
            DataLine = FileLine.strip().lower()

            if State == 0:
                if DataLine.startswith('mesh_vpn '):
                    State = 1

            elif State == 1:
                if DataLine.startswith('mtu '):
                    State = 2

            elif State == 2:
                if DataLine.startswith('fastd '):
                    State = 3

            elif State == 3:
                if DataLine.startswith('peers '):
                    State = 4

            elif State == 4:
                if GwTemplate.match(DataLine):
                    GwGroup = DataLine[:4]
                    State = 5

            elif State == 5:
                if DataLine.startswith('key '):
                    GwKey = DataLine.split('\'')[1]
                    GwKeyDict[GwGroup] = GwKey
                    State = 4

    print('... %d GW-Keys loaded.\n' % len(GwKeyDict))
    return GwKeyDict



#-----------------------------------------------------------------------
# Function "LoadMyKeys"
#
#   Load created fastd-keys from separate files
#
#   Parameter:
#   > KeyFilePath = Path to folder with key-files "vpn??.key"
#
#   return:
#     MyKeyDict { 'Public','Secret' }
#
#-----------------------------------------------------------------------
def LoadMyKeys(KeyFilePath):

    print('Loading my fastd-Keys from',KeyFilePath,'...')
    MyKeysDict = {}

    with open(KeyFilePath,'r') as KeyFile:
        KeyData = KeyFile.read()

        for FileLine in KeyData.split('\n'):
            if FileLine != '':
                DataLine = FileLine.strip().split(':')
                MyKeysDict[DataLine[0]] = DataLine[1].strip()

    return MyKeysDict



#-----------------------------------------------------------------------
# Function "WriteFastdGitFile"
#
#   Create and write fastd key-file for Git
#
#   Parameter:
#   > MyKeysDict = Dictionary with fastd-keys
#   > Segment    = Segment-Number
#   > GitPath    = Path to git Repository with peers-ffs
#   > MonitorID  = ID of FFS-Monitor
#
#-----------------------------------------------------------------------
def WriteFastdGitFile(MyKeysDict,Segment,GitPath,MonitorID):

    FilePath = '%s/vpn%02d/peers/ffs-020039%02dff%02d' % (GitPath,Segment,Segment,MonitorID)
    print('Writing fastd peer-file %s ...' % (FilePath))

    try:
        OutFile = open(FilePath, mode='w')
        OutFile.write('#MAC: 02:00:39:%02d:ff:%02d\n' % (Segment,MonitorID))
        OutFile.write('#Hostname: ffs-Monitor%02d-Seg%02d\n' % (MonitorID,Segment))
        OutFile.write('#Segment: fix %02d\n' % (Segment))
        OutFile.write('key \"%s\";\n' % (MyKeysDict['Public']))
        OutFile.close()
    except:
        print('++ ERROR on Fastd Peer File: %s' % (FilePath))

    return



#-----------------------------------------------------------------------
# Function "WriteFastdConfigFile"
#
#   Create and write fastd-config-file "/etc/fastd/vpn??/fastd.conf"
#
#   Parameter:
#   > MyKeysDict = Dictionary with fastd-keys
#   > Segment    = Segment-Number
#
#-----------------------------------------------------------------------
def WriteFastdConfigFile(MyKeysDict,Segment,WanInterface):

    print('Writing fastd-Configuration Files for Segment %02d ...' % (Segment))

    FileName = '/etc/fastd/vpn%02d/fastd.conf' % (Segment)
    os.makedirs(os.path.dirname(FileName), exist_ok=True)
#    print(FileName)

    try:
        OutFile = open(FileName, mode='w')
        OutFile.write('interface \"vpn%02d\";\n' % (Segment))
        OutFile.write('bind any:%d interface \"%s\" default ipv4;\n' % (10200+Segment,WanInterface))
        OutFile.write('status socket \"/var/run/fastd-vpn%02d.status\";\n' % (Segment))
        OutFile.write('method \"salsa2012+umac\";\n')
        OutFile.write('mtu 1340;\n')
#        OutFile.write('peer limit 2;\n')
        OutFile.write('secret \"%s\";\n' % (MyKeysDict['Secret']))
        OutFile.write('include peers from \"peers\";\n')
        OutFile.close()
    except:
        print('++ ERROR on FastdConfigFile: %s' % (FileName))

    return



#-----------------------------------------------------------------------
# Function "WriteFastdPeerFiles"
#
#   Create and write fastd-config-file "/etc/fastd/vpn??/peers/*"
#
#   Parameter:
#   > GwKeyDict  = Dictionary with Gateway-Keys
#   > Segment    = Segment-Number
#
#-----------------------------------------------------------------------
def WriteFastdPeerFiles(GwKeyDict,Segment):

    print('Writing fastd Peer-Files for Segment %02d ...' % (Segment))

    for Gateway in GwKeyDict:
        FileName = '/etc/fastd/vpn%02d/peers/%ss%02d' % (Segment,Gateway,Segment)
        os.makedirs(os.path.dirname(FileName), exist_ok=True)
        print(FileName)

        try:
            OutFile = open(FileName, mode='w')
            OutFile.write('#%ss%02d\n' % (Gateway,Segment))
            OutFile.write('key \"%s\";\n' % (GwKeyDict[Gateway]))
            OutFile.write('remote \"%ss%02d.gw.freifunk-stuttgart.de\" port %d;\n' % (Gateway,Segment,10200+Segment))
            OutFile.close()
        except:
            print('++ ERROR on FastdPeerFile: %s' % (FileName))

    return



#-----------------------------------------------------------------------
# Function "WriteNetworkFiles"
#
#   Create and write network-interface-file "/etc/network/interfaces.d/seg??"
#
#   Parameter:
#   > Segment    = Segment-Number
#   > MonitorID  = ID of FFS-Monitor
#
#-----------------------------------------------------------------------
def WriteNetworkFile(Segment,MonitorID):

    FileName = '/etc/network/interfaces.d/ffs%02d' % (Segment)
    print(FileName)

    try:
        OutFile = open(FileName, mode='w')
        OutFile.write('#-------------------------------------------------\n')
        OutFile.write('# Network Configuration for FFS-Segment %02d\n' % (Segment))
        OutFile.write('#-------------------------------------------------\n\n')
        OutFile.write('# batman-adv --------\n')
        OutFile.write('allow-hotplug   bat%02d\n' % (Segment))
        OutFile.write('iface bat%02d     inet6 static\n' % (Segment))
        OutFile.write('    hwaddress   02:00:39:%02d:ff:%02d\n' % (Segment,MonitorID))
        OutFile.write('    address     fd21:b4dc:4b%02d::ff39:ff%02d\n' % (Segment,MonitorID))
        OutFile.write('    netmask     64\n')
        OutFile.write('    pre-up      /sbin/modprobe batman_adv\n')
        OutFile.write('    post-up     /sbin/ip address add 10.190.%d.%d/21 broadcast 10.190.%d.255 dev $IFACE\n' % (8*(Segment-1),110+MonitorID,8*Segment - 1))
        OutFile.write('    post-up     /sbin/ip link set dev $IFACE up || true\n')
        OutFile.write('    post-up     /usr/sbin/batctl meshif $IFACE mff 0 || true\n')
        OutFile.write('    post-up     /usr/sbin/batctl meshif $IFACE it 10000 || true\n')
        OutFile.write('    post-up     /usr/sbin/batctl meshif $IFACE hp 255 || true\n\n')
        OutFile.write('# fastd VPN ---------\n')
        OutFile.write('allow-hotplug   vpn%02d\n' % (Segment))
        OutFile.write('iface vpn%02d     inet6 manual\n' % (Segment))
        OutFile.write('    hwaddress   02:00:33:%02d:ff:%02d\n' % (Segment,MonitorID))
        OutFile.write('    pre-up      /sbin/modprobe batman_adv\n')
        OutFile.write('    post-up     /usr/sbin/batctl meshif bat%02d if add $IFACE\n' % (Segment))
        OutFile.write('    post-up     /sbin/ip link set dev bat%02d up\n' % (Segment))
        OutFile.write('    pre-down    /usr/sbin/batctl meshif bat%02d if del $IFACE\n' % (Segment))
        OutFile.close()
    except:
        print('++ ERROR on NetworkInterfaceFile: %s' % (FileName))

    return



#=======================================================================
#
#   M a i n   P r o g r a m
#
#   Parameter:
#   > siteconf   = Path to "site.conf"
#   > vpnkeys    = Path to folder with own fastd-key-files
#
#=======================================================================
parser = argparse.ArgumentParser(description='Create configuration files for Freifunk Connection')
parser.add_argument('--monid', dest='MONITORID', action='store', required=True, help='ID of FFS-Monitor')
parser.add_argument('--siteconf', dest='SITECONF', action='store', required=True, help='site.conf')
parser.add_argument('--vpnkeys',dest='VPNKEYS', action='store', required=True, help='Own VPN Key Files')
parser.add_argument('--gitpeers',dest='GITPEERS', action='store', required=True, help='Git Repo with peers')

print('Creating configuration for VPN-Uplinks to Gateways ...\n')
args = parser.parse_args()
SiteConfPath = args.SITECONF

MonitorID = int(args.MONITORID)

if MonitorID < 1 or MonitorID > 9:
    print('++ Invalid Monitor-ID !!\n')
    exit(1)

WanInterface = GetWanInterface()

if WanInterface is None:
    print('++ No WAN-Interface available !!\n')
    exit(1)

KeyFileList  = glob(os.path.join(args.VPNKEYS, 'vpn*.key'))

if len(KeyFileList) < 20:
    print('++ Missing Fast Key-Files !!\n')
    exit(1)

print('... %d fastd Key-Files loaded.\n' % len(KeyFileList))

GwKeyDict = LoadGwKeys(SiteConfPath)

if len(GwKeyDict) < 10:
    print('++ Missing GW-Keys !!\n')
    exit(1)


for KeyFilePath in KeyFileList:
    MyKeysDict = LoadMyKeys(KeyFilePath)
    Segment  = int(os.path.basename(KeyFilePath).split('.')[0][3:])

    WriteFastdGitFile(MyKeysDict,Segment,args.GITPEERS,MonitorID)
    WriteFastdConfigFile(MyKeysDict,Segment,WanInterface)
    WriteFastdPeerFiles(GwKeyDict, Segment)
    WriteNetworkFile(Segment,MonitorID)

exit(0)
