#!/usr/bin/python3

###########################################################################################
#                                                                                         #
#  class_ffDHCPClient.py                                                                  #
#                                                                                         #
#  DHCP-Functions to Check DHCP-Relays of Freifunk Stuttgart Network.                     #
#                                                                                         #
#  Author: Roland Volkmann <roland.volkmann@t-online.de>                                  #
#                                                                                         #
#  This Code is based on "dhcpdoctor" (https://github.com/ArnesSI/dhcpdoctor)             #
#  Original License can be found below.                                                   #
#                                                                                         #
#  Requrements:                                                                           #
#                                                                                         #
#       scapy -> pip install scapy                                                        #
#                                                                                         #
###########################################################################################
#                                                                                         #
#  MIT License                                                                            #
#                                                                                         #
#  Copyright (c) 2019 Arnes                                                               #
#                                                                                         #
#  Permission is hereby granted, free of charge, to any person obtaining a copy           #
#  of this software and associated documentation files (the "Software"), to deal          #
#  in the Software without restriction, including without limitation the rights           #
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell              #
#  copies of the Software, and to permit persons to whom the Software is                  #
#  furnished to do so, subject to the following conditions:                               #
#                                                                                         #
#  The above copyright notice and this permission notice shall be included in all         #
#  copies or substantial portions of the Software.                                        #
#                                                                                         #
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR             #
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,               #
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE            #
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER                 #
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,          #
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE          #
#  SOFTWARE.                                                                              #
#                                                                                         #
###########################################################################################

import os

import binascii
import threading

from random import randint

from scapy.all import (
    BOOTP,
    DHCP,
    ARP,
    IP,
    UDP,
    Ether,
    conf,
    get_if_addr,
    get_if_hwaddr,
    sr1,
    sendp,
    sniff,
)



#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------
SNIFF_TIMEOUT = 1		# int: seconds to wait for a reply from server
ARP_RETRIES   = 3
DHCP_RETRIES  = 10




#==============================================================================
# "sniffer_thread"
#
#     Starts scapy sniffer and stops when a timeout is reached or a valid packet
#     is received.
#
#==============================================================================
def sniffer_thread(is_matching):

    sniff(
        timeout=SNIFF_TIMEOUT,
        stop_filter=is_matching,
        store=0
    )

#    print('    ... sniff() returned.')
    return





class DHCPClient:
    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self):

        self.xid = None
        self.sniffer = None
        self.offered_address = None
        self.offered_gateway = None
        return



    #-------------------------------------------------------------
    # private function "__craft_discover_request"
    #
    #     Generates a DHCPDICSOVER request
    #
    #     <  scapy.layers.inet.IP: DHCPDISCOVER packet
    #
    #-------------------------------------------------------------
    def __craft_discover_request(self):

        mac = get_if_hwaddr(conf.iface)

        if isinstance(mac, bytes):
            hw = mac
        elif isinstance(mac, str):
            hw = binascii.unhexlify(mac.replace(':', '').replace('-', '').replace('.', ''))
        else:
            raise TypeError('MAC address given must be a string')

        dhcp_request = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=hw, xid=self.xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        return dhcp_request



    #-------------------------------------------------------------
    # private function "__get_mac_of_ip"
    #
    #     Transmit ARP request
    #
    #-------------------------------------------------------------
    def __get_mac_of_ip(self, srv_ip):
        srv_mac = 'FF:FF:FF:FF:FF:FF'
        my_ip = get_if_addr(conf.iface)
        reply = None
        Retries = ARP_RETRIES

#        print('    ... sending ARP-Request %s -> %s ...' % (my_ip,srv_ip))

        while reply is None and Retries > 0:
            Retries -= 1
            reply = sr1(ARP(op='who-has', psrc=my_ip, pdst=srv_ip), timeout=1, verbose=False)

        if reply is not None:
            if reply.psrc == srv_ip:
                srv_mac = reply.hwsrc
#                print('    ++ ARP = %s -> %s' % (reply.hwsrc,reply.psrc))
            else:
                print('    !! ERROR on ARP: Invalid Response = %s -> %s' % (reply.hwsrc,reply.psrc))
        else:
            print('    !! ERROR on ARP: No Resonse for %s !!' % (srv_ip))

        return srv_mac



    #-------------------------------------------------------------
    # private function "__send_request"
    #
    #     Transmit DHCPDICSOVER request
    #
    #-------------------------------------------------------------
    def __send_request(self, srv_mac, srv_request):

        sendp(Ether(dst=srv_mac) / srv_request, verbose=False)
        return



    #-------------------------------------------------------------
    # private function "__is_offer_type"
    #
    #     Checks that packet is a valid DHCP reply
    #
    #-------------------------------------------------------------
    def __is_offer_type(self, packet):

        if not packet.haslayer(BOOTP):
            return False

        if packet[BOOTP].op != 2:   # BOOTREPLY
            return False

        if packet[BOOTP].xid != self.xid:
            return False

        if not packet.haslayer(DHCP):
            return False

        req_type = [x[1] for x in packet[DHCP].options if x[0] == 'message-type'][0]

        if req_type in [2]:
            return True

        return False



    #==============================================================================
    # public fuction "is_matching_reply"
    #
    #     Called for each packet captured by sniffer.
    #
    #==============================================================================
    def is_matching_reply(self, reply):

        if self.__is_offer_type(reply):
            self.offered_address = reply[BOOTP].yiaddr
            self.offered_gateway = reply[BOOTP].giaddr
            print('    %s from %s' % (self.offered_address, reply[BOOTP].giaddr))
            return True

        return False



    #-------------------------------------------------------------
    # private function "__sniff_start"
    #
    #     Starts listening for packets in a new thread
    #
    #-------------------------------------------------------------
    def __sniff_start(self):

        self.sniffer = threading.Thread(target=sniffer_thread,args=[self.is_matching_reply])
#        print('    ... Starting sniffer ...')
        self.sniffer.start()
        time.sleep(0.1)
        return


    #-------------------------------------------------------------
    # private function "__sniff_stop"
    #
    #     Waits for sniffer thread to finish
    #
    #-------------------------------------------------------------
    def __sniff_stop(self):

#        print('    ... waiting for sniff-result ...')
        self.sniffer.join()
#        print('    ... sniff_stop finished.\n')
        return



    #==============================================================================
    # public function "LocationDataOK"
    #
    #     Check for available Location Data
    #
    #==============================================================================
    def CheckDhcp(self, BatIF, srv_ip):

#        print('Starting DHCP-Check in IF = %s to Server = %s...' % (BatIF, srv_ip))

        conf.iface = BatIF
        conf.sniff_promisc = False

        self.offered_address = None
        self.offered_gateway = None
        self.xid = randint(0, (2 ** 32) - 1)  # BOOTP: 4 bytes

        Retries = DHCP_RETRIES

        while self.offered_address is None and Retries > 0:
            Retries -= 1
            dhcp_request = self.__craft_discover_request()
            srv_mac      = self.__get_mac_of_ip(srv_ip)

            self.__sniff_start()
            self.__send_request(srv_mac, dhcp_request)
            self.__sniff_stop()

        if self.offered_address is not None and self.offered_gateway != srv_ip:
            print('    !! Reply from wrong Gateway: IP = %s / GW = %s' % (self.offered_address,self.offered_gateway))

        return self.offered_address
