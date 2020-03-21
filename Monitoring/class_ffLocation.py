#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  class_ffLocation.py                                                                    #
#                                                                                         #
#  Get Region and ZIP-Area from Coordiantes.                                              #
#                                                                                         #
#                                                                                         #
#  Needed Data Files:                                                                     #
#                                                                                         #
#       regions/<segment>/*.json   -> Polygons of Regions                                 #
#       database/ZipLocations.json -> Dict. of ZIP-Codes with related GPS-Positions       #
#       database/ZipGrid.json      -> Dict. of Grids with ZIP-Codes                       #
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
import json

from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
from glob import glob



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------
Region2ZipName = 'Region2ZIP.json'    # Regions with ZIP Codes of Baden-Wuerttemberg
Zip2GpsName    = 'ZipLocations.json'  # GPS location of ZIP-Areas based on OpenStreetMap and OpenGeoDB
ZipGridName    = 'ZipGrid.json'       # Grid of ZIP Codes from Baden-Wuerttemberg





class ffLocation:

    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self,DatabasePath,GitPath):

        # private Attributes
        self.__DatabasePath = DatabasePath
        self.__GitPath      = GitPath

        self.Zip2PosDict    = None        # Zip2PosDict[ZipCode] = (lon, lat)
        self.ZipAreaDict    = None        # ZipAreaDict[ZipCode] = {'FileName', 'Area', 'Segment'}
        self.ZipGridDict    = None
        self.RegionDict     = None        # {ValidArea, Polygons[Region], Segments[Region], RegionList[]}

        # Initializations
        self.__SetupZip2PosData()
        self.__SetupZipAreaData()
        self.__SetupZipGridData()
        self.__SetupRegionData()
        return



    #-------------------------------------------------------------
    # private function "__SetupZip2PosData"
    #
    #     Load ZIP File of OpenGeoDB Project
    #
    #-------------------------------------------------------------
    def __SetupZip2PosData(self):

        print('Setting up ZIP-to-Position Data ...')

        ZipCount = 0

        try:
            with open(os.path.join(self.__DatabasePath,Zip2GpsName), mode='r') as Zip2GpsFile:
                self.Zip2PosDict = json.load(Zip2GpsFile)
        except:
            print('!! ERROR on setting up ZIP-to-Position Data')
            self.Zip2PosDict = None
        else:
            ZipCount = len(self.Zip2PosDict)

        print('... ZIP-Codes loaded: %d\n' % (ZipCount))
        return



    #-------------------------------------------------------------
    # private function "__SetupZipAreaData"
    #
    #     ZipAreaDict -> Dictionary of ZIP-Area Files
    #
    #-------------------------------------------------------------
    def __SetupZipAreaData(self):

        print('Setting up ZIP-Area Data ...')

        ZipAreaFiles = glob(os.path.join(self.__GitPath,'vpn*/zip-areas/?????_*.json'))
        self.ZipAreaDict  = {}

        for FileName in ZipAreaFiles:
            ZipCode = os.path.basename(FileName)[:5]
            self.ZipAreaDict[ZipCode] = { 'FileName':FileName, 'Area':os.path.basename(FileName).split(".")[0], 'Segment':int(FileName.split("/")[-3][3:]) }

            if ZipCode not in self.Zip2PosDict:
                print('!! ZIP-Code w/o GPS-Data: %s' % (ZipCode))

        if len(self.ZipAreaDict) < 10:
            print('!! ERROR on registering ZIP-Areas: No. of Records = %d\n' % (len(self.ZipAreaDict)))
            self.ZipAreaDict = None
        else:
            print('... ZIP-Areas registered: %d\n' % (len(self.ZipAreaDict)))

        return



    #-------------------------------------------------------------
    # private function "__SetupZipGridData"
    #
    #     ZipGridDict -> Grid with ZIP-Codes
    #
    #-------------------------------------------------------------
    def __SetupZipGridData(self):

        print('Setting up ZIP-Grid Data ...')

        FieldCount  = 0

        try:
            with open(os.path.join(self.__DatabasePath,ZipGridName), mode='r') as ZipGridFile:
                self.ZipGridDict = json.load(ZipGridFile)
        except:
            print('!! ERROR on setting up ZIP-Grid Data')
            self.ZipGridDict = None
        else:
            FieldCount = len(self.ZipGridDict['Fields'])

            lon_min = float(self.ZipGridDict['Meta']['lon_min'])
            lon_max = float(self.ZipGridDict['Meta']['lon_max'])
            lat_min = float(self.ZipGridDict['Meta']['lat_min'])
            lat_max = float(self.ZipGridDict['Meta']['lat_max'])

            self.ZipGridDict['Meta']['lon_scale'] = float(self.ZipGridDict['Meta']['lon_fields']) / (lon_max - lon_min)
            self.ZipGridDict['Meta']['lat_scale'] = float(self.ZipGridDict['Meta']['lat_fields']) / (lat_max - lat_min)

            for FieldIndex in self.ZipGridDict['Fields']:
                for ZipCode in self.ZipGridDict['Fields'][FieldIndex]:
                    if ZipCode not in self.ZipAreaDict:
                        print('!! Unknown ZIP-Code in ZIP-Grid: %s' % (ZipCode))

        print('... ZIP-Fields loaded: %d\n' % (FieldCount))
        return



    #-------------------------------------------------------------
    # private function "__SetupRegionData"
    #
    #     Load Region Json Files and setup polygons
    #
    #-------------------------------------------------------------
    def __SetupRegionData(self):

        print('Setting up Region Data ...')

        self.RegionDict = {
            'ValidArea': {},
            'Polygons' : {},
            'Segments' : {},
            'ZipRegions': []
        }

        lon_min = 99.0
        lon_max =  0.0

        lat_min = 99.0
        lat_max =  0.0


        JsonFileList = glob(os.path.join(self.__GitPath,'vpn*/regions/*.json'))
        RegionCount = 0

        try:
            for FileName in JsonFileList:
                Region  = os.path.basename(FileName).split('.')[0]
                Segment = int(os.path.dirname(FileName).split('/')[-2][3:])

                with open(FileName,'r') as JsonFile:
                    GeoJson = json.load(JsonFile)

                if 'type' in GeoJson and 'geometries' in GeoJson:
                    TrackBase = GeoJson['geometries'][0]['coordinates']
                elif 'coordinates' in GeoJson:
                    TrackBase = GeoJson['coordinates']
                else:
                    TrackBase = None
                    print('Problem parsing %s' % FileName)
                    continue

                self.RegionDict['Polygons'][Region] = []
                self.RegionDict['Segments'][Region] = Segment
                RegionCount += 1

                for Track in TrackBase:
                    Shape = []

                    for t in Track[0]:
                        Shape.append( (t[0],t[1]) )    # t[0] = Longitude = x | t[1] = Latitude = y

                        if t[0] < lon_min:  lon_min = t[0]
                        if t[0] > lon_max:  lon_max = t[0]

                        if t[1] < lat_min:  lat_min = t[1]
                        if t[1] > lat_max:  lat_max = t[1]

                    self.RegionDict['Polygons'][Region].append(Polygon(Shape))

        except:
            RegionCount = 0

        print('>> lon = (%f, %f) / lat = (%f, %f)' % (lon_min, lon_max, lat_min, lat_max))
        self.RegionDict['ValidArea']['lon_min'] = lon_min -  0.1
        self.RegionDict['ValidArea']['lon_max'] = lon_max +  0.1
        self.RegionDict['ValidArea']['lat_min'] = lat_min -  0.1
        self.RegionDict['ValidArea']['lat_max'] = lat_max +  0.1

        self.RegionDict['ValidArea']['Polygon'] = Polygon([ (lon_min,lat_min),(lon_min,lat_max),(lon_max,lat_max),(lon_max,lat_min) ])


        try:
            with open(os.path.join(self.__DatabasePath,Region2ZipName), mode='r') as Region2ZipFile:
                Region2ZipDict = json.load(Region2ZipFile)
        except:
            print('!! ERROR on loading Region-to-ZIP Data')
        else:
            for Region in Region2ZipDict:
                self.RegionDict['ZipRegions'].append(Region)

                if Region not in self.RegionDict['Segments'] or Region not in self.RegionDict['Polygons']:
                    RegionCount = 0
                    print('!! Missing Region Data: %s' % (Region))
                else:
                    for ZipCode in Region2ZipDict[Region]:
                        if ZipCode in self.ZipAreaDict:
                            if self.ZipAreaDict[ZipCode]['Segment'] != self.RegionDict['Segments'][Region]:
                                RegionCount = 0
                                print('!! Region Segment Mismatch: Region = %s / RegSeg = %02d <-> ZipSeg = %02d' %
                                    (Region,self.RegionDict['Segments'][Region],self.ZipAreaDict[ZipCode]['Segment']))
                        else:
                            print('!! Unknown Zip-Code in RegionDict: Region = %s / ZIP = %s' % (Region,ZipCode))

        if RegionCount == 0:
            self.RegionDict = None

        print('... Region Areas loaded: %d\n' % (RegionCount))
        return


    #-------------------------------------------------------------
    # private function "__GetZipFromGPS"
    #
    #     Get ZIP-Code from GPS using ZIP polygons
    #
    #-------------------------------------------------------------
    def __GetZipFromGPS(self,lon,lat):

        ZipCodeResult = None

        x = int((lon - float(self.ZipGridDict['Meta']['lon_min'])) * self.ZipGridDict['Meta']['lon_scale'])
        y = int((lat - float(self.ZipGridDict['Meta']['lat_min'])) * self.ZipGridDict['Meta']['lat_scale'])

        if ((x >= 0 and x < self.ZipGridDict['Meta']['lon_fields']) and
            (y >= 0 and y < self.ZipGridDict['Meta']['lat_fields'])):

            NodeLocation = Point(lon,lat)
            FieldIndex = str(y * self.ZipGridDict['Meta']['lon_fields'] + x)

            for ZipCode in self.ZipGridDict['Fields'][FieldIndex]:
                ZipFileName = self.ZipAreaDict[ZipCode]['FileName']
                ZipAreaJson = None

                with open(ZipFileName,"r") as fp:
                    ZipAreaJson = json.load(fp)

                if "geometries" in ZipAreaJson:
                    TrackBase = ZipAreaJson["geometries"][0]["coordinates"]
                elif "coordinates" in ZipAreaJson:
                    TrackBase = ZipJson["coordinates"]
                else:
                    TrackBase = None
                    print('Problem parsing %s' % ZipFileName)
                    continue

                AreaMatch = 0

                for Track in TrackBase:
                    Shape = []

                    for t in Track[0]:
                        Shape.append( (t[0],t[1]) )

                    ZipPolygon = Polygon(Shape)

                    if ZipPolygon.intersects(NodeLocation):
                        AreaMatch += 1

                if AreaMatch == 1:
                    ZipCodeResult = ZipCode
                    break

        return ZipCodeResult



    #==============================================================================
    # Method "LocationDataOK"
    #
    #     Check for available Location Data
    #
    #==============================================================================
    def LocationDataOK(self):

        OK = self.RegionDict is not None and self.Zip2PosDict is not None and self.ZipAreaDict is not None and self.ZipGridDict is not None
        return OK



    #==============================================================================
    # Method "GetLocationDataFromGPS"
    #
    #     Get Location-Data from GPS using area polygons
    #
    #==============================================================================
    def GetLocationDataFromGPS(self,lon,lat):

        GpsZipCode = None
        GpsRegion  = None
        GpsSegment = None

        if lat is not None and lon is not None:

            if ((lon > self.RegionDict['ValidArea']['lon_min'] and lon < self.RegionDict['ValidArea']['lon_max']) and
                (lat > self.RegionDict['ValidArea']['lat_min'] and lat < self.RegionDict['ValidArea']['lat_max'])):
                #--- Longitude and Latitude are within valid area ---
                NodeLocation = Point(lon,lat)
                GpsZipCode = self.__GetZipFromGPS(lon,lat)

            elif ((lon > self.RegionDict['ValidArea']['lat_min'] and lon < self.RegionDict['ValidArea']['lat_max']) and
                  (lat > self.RegionDict['ValidArea']['lon_min'] and lat < self.RegionDict['ValidArea']['lon_max'])):
                #--- Longitude and Latitude are mixed up ---
                NodeLocation = Point(lat,lon)
                GpsZipCode = self.__GetZipFromGPS(lat,lon)

            else:
                print('*** Invalid GPS: %f, %f' % (lon,lat))
                while lon > self.RegionDict['ValidArea']['lon_max']:  lon /= 10.0    # missing decimal separator
                while lat > self.RegionDict['ValidArea']['lat_max']:  lat /= 10.0    # missing decimal separator

                NodeLocation = Point(lon,lat)
                GpsZipCode = self.__GetZipFromGPS(lon,lat)


            if GpsZipCode is not None:
                GpsRegion  = self.ZipAreaDict[GpsZipCode]['Area']
                GpsSegment = self.ZipAreaDict[GpsZipCode]['Segment']

            elif self.RegionDict['ValidArea']['Polygon'].intersects(NodeLocation):
                for Region in self.RegionDict['Polygons']:

                    if Region not in self.RegionDict['ZipRegions']:
                        MatchCount = 0

                        for RegionPart in self.RegionDict['Polygons'][Region]:
                            if RegionPart.intersects(NodeLocation):
                                MatchCount += 1

                        if MatchCount == 1:
                            GpsRegion  = Region
                            GpsSegment = self.RegionDict['Segments'][Region]
                            break

        return (GpsZipCode,GpsRegion,GpsSegment)



    #==============================================================================
    # Method "GetLocationDataFromZIP"
    #
    #     Get Location-Data from ZIP using area polygons
    #
    #==============================================================================
    def GetLocationDataFromZIP(self,ZipCode):

        ZipRegion  = None
        ZipSegment = None

        if ZipCode in self.ZipAreaDict:
            ZipRegion = self.ZipAreaDict[ZipCode]['Area']
            ZipSegment = self.ZipAreaDict[ZipCode]['Segment']

        elif ZipCode in self.Zip2PosDict:
            lon = self.Zip2PosDict[ZipCode][0]
            lat = self.Zip2PosDict[ZipCode][1]

            (GpsZipCode,ZipRegion,ZipSegment) = self.GetLocationDataFromGPS(lon,lat)

            if GpsZipCode is not None and GpsZipCode != ZipCode:
                    print('!! Inconsistant Zip-Data: %s / %s' % (ZipCode,GpsZipCode))

        return (ZipRegion,ZipSegment)
