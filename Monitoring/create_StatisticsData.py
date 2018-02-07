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
#      --statistics = Path+Filename to Statistics.json                                    #
#                                                                                         #
###########################################################################################
#                                                                                         #
#  Copyright (c) 2018, Roland Volkmann <roland.volkmann@t-online.de>                      #
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

import json
import re
import argparse

from glob import glob


PlzTemplate = re.compile('^[0-9]{5}')



#-----------------------------------------------------------------------
# Function "GetCurrentLoadDict"
#
#   Get Load Data from NodeDict.json
#
#-----------------------------------------------------------------------
def GetCurrentLoadDict(NodeDictName):

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

                ZipCode = str(NodeDict[NodeID]['ZIP'])
                Segment = str(NodeDict[NodeID]['Segment'])
                Region  = str(NodeDict[NodeID]['Region'])

                #----- Segments -----
                if Segment not in LoadDict['Segments']:
                    LoadDict['Segments'][Segment] = 0

                LoadDict['Segments'][Segment] += NodeDict[NodeID]['Clients'] + 1

                if Segment == '09': continue    # BSZ Leonberg


                #----- Regions -----
                if Region not in LoadDict['Regions']:
                    LoadDict['Regions'][Region] = 0

                LoadDict['Regions'][Region] += NodeDict[NodeID]['Clients'] + 1

                if PlzTemplate.match(Region):
                    if Region[:5] != ZipCode:
                        print('>>> ZIP Mismatch:',NodeID,'->',Region,'<>',ZipCode)

                #----- ZipAreas -----
                if not PlzTemplate.match(ZipCode):
                    ZipCode = '-----'

                if ZipCode not in LoadDict['ZipAreas']:
                    LoadDict['ZipAreas'][ZipCode] = 0

                LoadDict['ZipAreas'][ZipCode] += NodeDict[NodeID]['Clients'] + 1

        print('... StatLoadDict loaded: S = %d / R = %d / Z = %d\n' % (len(LoadDict['Segments']),len(LoadDict['Regions']),len(LoadDict['ZipAreas'])))

    return LoadDict


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

if args.NodeFile is None:
    NodeFileName = 'NodeDict.json'
else:
    NodeFileName = args.NodeFile

LoadDict = GetCurrentLoadDict(NodeFileName)


if args.RegionFile is None:
    RegionFileName = 'Region2ZIP.json'
else:
    RegionFileName = args.RegionFile

Zip2RegionDict = GetZip2RegionDict(RegionFileName)

if Zip2RegionDict is None:
    print('++ ERROR: Region-Data not available!')
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
        StatisticsDict['Segments'][Segment] = 0

    if LoadDict['Segments'][Segment] > StatisticsDict['Segments'][Segment]:
        StatisticsDict['Segments'][Segment] = LoadDict['Segments'][Segment]

print('Total Segment Load =',TotalLoad)


#---------- Regions ----------
TotalLoad  = 0
RegionLoad = {}
ZipRegions = []

for Region in LoadDict['Regions']:
    if PlzTemplate.match(Region):
        ZipCode = Region[:5]

        if ZipCode in Zip2RegionDict:
            StatisticsRegion = Zip2RegionDict[ZipCode]
        else:
            print('>>> Unknown Region for ZIP:',Region,'->',ZipCode)
            StatisticsRegion = '??'

        if StatisticsRegion not in RegionLoad:
            RegionLoad[StatisticsRegion] = 0

        RegionLoad[StatisticsRegion] += LoadDict['Regions'][Region]
        ZipRegions.append(Region)

for Region in RegionLoad:
    if Region not in LoadDict['Regions']:
        LoadDict['Regions'][Region] = 0

    LoadDict['Regions'][Region] += RegionLoad[Region]

for Region in ZipRegions:
    del LoadDict['Regions'][Region]


for Region in LoadDict['Regions']:
    TotalLoad += LoadDict['Regions'][Region]

    if Region not in StatisticsDict['Regions']:
        StatisticsDict['Regions'][Region] = 0

    if LoadDict['Regions'][Region] > StatisticsDict['Regions'][Region]:
        StatisticsDict['Regions'][Region] = LoadDict['Regions'][Region]

print('Total Region Load  =',TotalLoad)


#---------- ZipAreas ----------
TotalLoad = 0

for ZipCode in LoadDict['ZipAreas']:
    TotalLoad += LoadDict['ZipAreas'][ZipCode]

    if ZipCode not in StatisticsDict['ZipAreas']:
        StatisticsDict['ZipAreas'][ZipCode] = 0

    if LoadDict['ZipAreas'][ZipCode] > StatisticsDict['ZipAreas'][ZipCode]:
        StatisticsDict['ZipAreas'][ZipCode] = LoadDict['ZipAreas'][ZipCode]

print('Total ZipArea Load =',TotalLoad)


print('\nData Records available: Segments = %d, Regions = %d, ZipAreas = %d\n' % (len(LoadDict['Segments']),len(LoadDict['Regions']),len(LoadDict['ZipAreas'])))

JsonFile = open(StatisticsFileName, mode='w+')
json.dump(StatisticsDict,JsonFile)
JsonFile.close()

exit(0)
