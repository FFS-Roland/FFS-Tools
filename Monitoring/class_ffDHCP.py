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
    DUID_LL,
    IP,
    UDP,
    AnsweringMachine,
    Ether,
    conf,
    get_if_addr,
    get_if_hwaddr,
    get_if_raw_hwaddr,
    send,
    sendp,
    sniff,
)


#-------------------------------------------------------------
# Global Constants
#-------------------------------------------------------------
SNIFF_TIMEOUT = 2		# int: seconds to wait for a reply from server



class DHCPClient:
    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self):

        self.xid = None
        self.relay_mode  = False
        self.request = None
        self.reply = None
        self.sniffer = None
        self.offered_address = None
        return



    #-------------------------------------------------------------
    # private function "__craft_discover"
    #
    #     Generates a DHCPDICSOVER packet
    #
    #     <  scapy.layers.inet.IP: DHCPDISCOVER packet
    #
    #-------------------------------------------------------------
    def __craft_discover(self):

        mac = get_if_hwaddr(conf.iface)

        if isinstance(mac, bytes):
            hw = mac
        elif isinstance(mac, str):
            hw = binascii.unhexlify(mac.replace(':', '').replace('-', '').replace('.', ''))
        else:
            raise TypeError('MAC address given must be a string')

        dhcp_discover = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=hw, xid=self.xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        return dhcp_discover


    #-------------------------------------------------------------
    # private function "__add_relay"
    #
    #     Modify passed DHCP client packet as if a DHCP relay would
    #
    #-------------------------------------------------------------
    def __add_relay(self, p, srv_ip):

        relay_ip = get_if_addr(conf.iface)

        p[BOOTP].giaddr = relay_ip
        p[BOOTP].flags = 0  # unset broadcast flag
        p[UDP].sport = 67
        p[IP].src = relay_ip
        p[IP].dst = srv_ip

        self.relay_mode = True
        return


    #-------------------------------------------------------------
    # private function "__craft_request"
    #
    #     Generates a DHCPDICSOVER request
    #
    #-------------------------------------------------------------
    def __craft_request(self, srv_ip):

        self.request = self.__craft_discover()

        if srv_ip is not None:
            self.__add_relay(self.request, srv_ip)

        return self.request


    #-------------------------------------------------------------
    # private function "__send_request"
    #
    #     Transmit DHCPDICSOVER request
    #
    #-------------------------------------------------------------
    def __send_request(self):
        if self.relay_mode:
            # sending unicast, let scapy handle ethernet
            send(self.request, verbose=False)
        else:
            # sending to local link, need to set Ethernet ourselves
            sendp(Ether(dst='FF:FF:FF:FF:FF:FF') / self.request, verbose=False)

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
        if packet[BOOTP].op != 2:
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
            self.reply = reply
            self.offered_address = reply[BOOTP].yiaddr
            return True

        return False



    #==============================================================================
    # public function "sniffer_thread"
    #
    #     Starts scapy sniffer and stops when a timeout is reached or a valid packet
    #     is received.
    #
    #==============================================================================
    def sniffer_thread(self):

        sniff(
            timeout=SNIFF_TIMEOUT,
            stop_filter=self.is_matching_reply,
        )



    #-------------------------------------------------------------
    # private function "__sniff_start"
    #
    #     Starts listening for packets in a new thread
    #
    #-------------------------------------------------------------
    def __sniff_start(self):

        self.sniffer = threading.Thread(target=self.sniffer_thread)
        self.sniffer.start()
        return


    #-------------------------------------------------------------
    # private function "__sniff_stop"
    #
    #     Waits for sniffer thread to finish
    #
    #-------------------------------------------------------------
    def __sniff_stop(self):

        self.sniffer.join()
        return




    #==============================================================================
    # public function "LocationDataOK"
    #
    #     Check for available Location Data
    #
    #==============================================================================
    def CheckDhcp(self, BatIF, srv_ip):

        self.xid = randint(0, (2 ** 24) - 1)  # BOOTP 4 bytes, DHCPv6 3 bytes
        self.relay_mode  = False
        self.request = None
        self.reply = None
        self.sniffer = None
        self.offered_address = None

        conf.iface = BatIF

        self.__craft_request(srv_ip)

        self.__sniff_start()
        self.__send_request()
        self.__sniff_stop()

        return self.offered_address
