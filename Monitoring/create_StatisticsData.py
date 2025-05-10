#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  create_StatisticsData.py                                                               #
#                                                                                         #
#  Analyzing NodeDict.json and creating Statistics Data as json-File.                     #
#                                                                                         #
#  Parameter:                                                                             #
#                                                                                         #
#      --nodefile   = Path+Filename to NodeDict.json                                      #
#      --regions    = Path+Filename to Region2Zip.json                                    #
#      --statistics = Path+Filename to Statistics.json                                    #
#                                                                                         #
###########################################################################################

import os
import time
import datetime

import json
import re
import argparse



PlzTemplate = re.compile('^[0-9]{5}')

SegIgnoreList = ['21','22','30']    # e.g. Single Nodes (Schools)



#-----------------------------------------------------------------------
# Function "GetZip2RegionDict"
#
#   Setup Zip2RegionDict from Region2Zip.json
#
#-----------------------------------------------------------------------
def GetZip2RegionDict(RegionFileName):

    print('Loading Region2Zip.json ...')
    Zip2RegionDict = {}

    try:
        JsonFile = open(RegionFileName, mode='r')
        Region2ZipDict = json.load(JsonFile)
        JsonFile.close()

    except:
        print('!! Error on Reading Region2Zip.json!\n')
        Zip2RegionDict = {}
    else:
        for Region in Region2ZipDict:
            for ZipCode in Region2ZipDict[Region]:
                Zip2RegionDict[ZipCode] = Region

    return Zip2RegionDict



#-----------------------------------------------------------------------
# Function "CreateCurrentLoadDict"
#
#   Get Load Data from NodeDict.json
#
#-----------------------------------------------------------------------
def CreateCurrentLoadDict(NodeDictName,Zip2RegionDict):

    print('Loading NodeDict.json ...')
    OnlineStates       = [' ','V']      # online, online with VPN-Uplink

    NodeDict = None
    LoadDict = None

    try:
        JsonFile = open(NodeDictName, mode='r')
        NodeDict = json.load(JsonFile)
        JsonFile.close()

    except:
        print('!! Error on Reading NodeDict.json!\n')
        NodeDict = None
    else:
        print('... %d Node Infos loaded.' % (len(NodeDict)))
        LoadDict = { 'Segments':{}, 'Regions':{}, 'ZipAreas':{}}

        for NodeID in NodeDict:
            if NodeDict[NodeID]['Status'] in OnlineStates:

                if NodeDict[NodeID]['Segment'] is None:
                    print('++ Node w/o Segment:',NodeDict[NodeID])
                    continue

                ZipCode = str(NodeDict[NodeID]['ZIP'])
                Segment = '%02d' % (NodeDict[NodeID]['Segment'])

                if Segment in SegIgnoreList: continue


                #----- Segments -----
                if Segment not in LoadDict['Segments']:
                    LoadDict['Segments'][Segment] = 0

                LoadDict['Segments'][Segment] += NodeDict[NodeID]['Clients'] + 1

                #----- ZipAreas -----
                if not PlzTemplate.match(ZipCode):
                    ZipCode = '-----'

                if ZipCode not in LoadDict['ZipAreas']:
                    LoadDict['ZipAreas'][ZipCode] = 0

                LoadDict['ZipAreas'][ZipCode] += NodeDict[NodeID]['Clients'] + 1

                #----- Regions -----
                if ZipCode in Zip2RegionDict:
                    Region = Zip2RegionDict[ZipCode]
                else:
                    Region = '??'

                if Region not in LoadDict['Regions']:
                    LoadDict['Regions'][Region] = 0

                LoadDict['Regions'][Region] += NodeDict[NodeID]['Clients'] + 1

        print('... StatLoadDict loaded: S = %d / R = %d / Z = %d\n' % (len(LoadDict['Segments']),len(LoadDict['Regions']),len(LoadDict['ZipAreas'])))

    return LoadDict



#-----------------------------------------------------------------------
# Function "LoadStatisticsDict"
#
#   Load Data from StatisticsDict.json
#
#-----------------------------------------------------------------------
def LoadStatisticsDict(StatisticsDictName):

    print('Loading Statistics.json ...')
    StatisticsDict = {}

    try:
        JsonFile = open(StatisticsDictName, mode='r')
        StatisticsDict = json.load(JsonFile)
        JsonFile.close()

    except:
        print('... No existing StatisticsDict - creating new one ...\n')
        StatisticsDict = {}

    if 'Segments' not in StatisticsDict or 'Regions' not in StatisticsDict or 'ZipAreas'not in StatisticsDict:
        print('... No correct Statisics Infos -  will be reset.\n')
        StatisticsDict = { 'Segments':{}, 'Regions':{}, 'ZipAreas':{}}
    else:
        print('... Statisics Infos loaded: S = %d / R = %d / Z = %d\n' % (len(StatisticsDict['Segments']),len(StatisticsDict['Regions']),len(StatisticsDict['ZipAreas'])))

    return StatisticsDict



#=======================================================================
#
#  M a i n   P r o g r a m
#
#=======================================================================
print('\nCreating / Updating Statistics Data\n')

parser = argparse.ArgumentParser(description='Create and/or update Statistcs Data from NodeDict')
parser.add_argument('--nodefile', dest='NodeFile', action='store', help='Input = NodeDictFile Name')
parser.add_argument('--regions', dest='RegionFile', action='store', help='Input = Region2ZipFile Name')
parser.add_argument('--statistics', dest='StatisticsFile', action='store', help='Output = StatisticsFile Name')

args = parser.parse_args()

if args.RegionFile is None:
    RegionFileName = 'Region2ZIP.json'
else:
    RegionFileName = args.RegionFile

Zip2RegionDict = GetZip2RegionDict(RegionFileName)

if Zip2RegionDict is None:
    print('++ ERROR: Region-Data not available!')
    exit(1)


if args.NodeFile is None:
    NodeFileName = 'NodeDict.json'
else:
    NodeFileName = args.NodeFile

LoadDict = CreateCurrentLoadDict(NodeFileName,Zip2RegionDict)

if LoadDict is None:
    print('++ ERROR: Node and Load Data not available!')
    exit(1)


if args.StatisticsFile is None:
    StatisticsFileName = 'StatisticsDict.json'
else:
    StatisticsFileName = args.StatisticsFile

StatisticsDict = LoadStatisticsDict(StatisticsFileName)


#---------- Segments ----------
TotalLoad = 0
for Segment in LoadDict['Segments']:
    TotalLoad += LoadDict['Segments'][Segment]

    if Segment not in StatisticsDict['Segments']:
        StatisticsDict['Segments'][Segment] = LoadDict['Segments'][Segment]
    elif LoadDict['Segments'][Segment] > StatisticsDict['Segments'][Segment]:
        StatisticsDict['Segments'][Segment] = int((StatisticsDict['Segments'][Segment] * 3 + LoadDict['Segments'][Segment]) / 4 + 0.5)
    else:
        StatisticsDict['Segments'][Segment] = int((StatisticsDict['Segments'][Segment] * 431 + LoadDict['Segments'][Segment]) / 432 + 0.5)

print('Total Segment Load =',TotalLoad)


#---------- Regions ----------
TotalLoad  = 0
for Region in LoadDict['Regions']:
    TotalLoad += LoadDict['Regions'][Region]

    if Region not in StatisticsDict['Regions']:
        StatisticsDict['Regions'][Region] = LoadDict['Regions'][Region]
    elif LoadDict['Regions'][Region] > StatisticsDict['Regions'][Region]:
        StatisticsDict['Regions'][Region] = int((StatisticsDict['Regions'][Region] * 3 + LoadDict['Regions'][Region]) / 4 + 0.5)
    else:
        StatisticsDict['Regions'][Region] = int((StatisticsDict['Regions'][Region] * 431 + LoadDict['Regions'][Region]) / 432 + 0.5)

print('Total Region Load  =',TotalLoad)


#---------- ZipAreas ----------
TotalLoad = 0

for ZipCode in LoadDict['ZipAreas']:
    TotalLoad += LoadDict['ZipAreas'][ZipCode]

    if ZipCode not in StatisticsDict['ZipAreas']:
        StatisticsDict['ZipAreas'][ZipCode] = LoadDict['ZipAreas'][ZipCode]
    elif LoadDict['ZipAreas'][ZipCode] > StatisticsDict['ZipAreas'][ZipCode]:
        StatisticsDict['ZipAreas'][ZipCode] = int((StatisticsDict['ZipAreas'][ZipCode] * 3 + LoadDict['ZipAreas'][ZipCode]) / 4 + 0.5)
    else:
        StatisticsDict['ZipAreas'][ZipCode] = int((StatisticsDict['ZipAreas'][ZipCode] * 431 + LoadDict['ZipAreas'][ZipCode]) / 432 + 0.5)

print('Total ZipArea Load =',TotalLoad)


print('\nData Records available: Segments = %d, Regions = %d, ZipAreas = %d\n' % (len(LoadDict['Segments']),len(LoadDict['Regions']),len(LoadDict['ZipAreas'])))

JsonFile = open(StatisticsFileName, mode='w+')
json.dump(StatisticsDict,JsonFile)
JsonFile.close()

exit(0)
