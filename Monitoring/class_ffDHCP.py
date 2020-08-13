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
#       tcpdump                                                                           #
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
SNIFF_TIMEOUT = 10		# int: seconds to wait for reply from server
ARP_RETRIES   = 3





class DHCPClient:
    #==========================================================================
    # Constructor
    #==========================================================================
    def __init__(self):

        self.xid = 0
        self.sniffer = None
        self.reply_packet = None
        return



    #==============================================================================
    # thread "sniffer_thread"
    #
    #     Starts scapy sniffer and stops when a timeout is reached or a valid packet
    #     is received.
    #
    #==============================================================================
    def sniffer_thread(self,sniff_interface,sniff_filter):

#        print('\n    ... starting sniff()on %s with filter = \"%s\" ...' % (sniff_interface,sniff_filter))

        sniff(
            timeout=SNIFF_TIMEOUT,
            iface=sniff_interface,
            filter=sniff_filter,
            prn=self.process_packet,
            count=1,
            store=0
        )

#        print('    ... sniff() returned.')
        return



    #==============================================================================
    # public function "process_packet"
    #
    #     Called for packet captured by sniffer.
    #
    #==============================================================================
    def process_packet(self, packet):

        self.reply_packet = packet
#        print('    ... got packet.')
        return




    #-------------------------------------------------------------
    # private function "__craft_discover_request"
    #
    #     Generates a DHCPDICSOVER request
    #
    #     <  scapy.layers.inet.IP: DHCPDISCOVER packet
    #
    #-------------------------------------------------------------
    def __craft_discover_request(self,dhcp_interface):

        self.xid = randint(0, (2 ** 32) - 1)  # BOOTP: 4 bytes
        conf.iface = dhcp_interface
        mac = get_if_hwaddr(dhcp_interface)

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
    def __get_mac_of_ip(self,my_iface,srv_ip):
        srv_mac = 'FF:FF:FF:FF:FF:FF'
        my_ip = get_if_addr(my_iface)
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
    # private function "__sniff_start"
    #
    #     Starts listening for packets in a new thread
    #
    #-------------------------------------------------------------
    def __sniff_start(self,sniff_interface,srv_ip):

        conf.sniff_promisc = False
        sniff_filter = 'udp and src host %s and port 67' % (srv_ip)
        self.reply_packet = None

        self.sniffer = threading.Thread(target=self.sniffer_thread,args=[sniff_interface,sniff_filter])
        self.sniffer.start()
        time.sleep(0.1)
        return



    #-------------------------------------------------------------
    # private function "__is_offer_type"
    #
    #     Checks that packet is a valid DHCP_OFFER
    #
    #-------------------------------------------------------------
    def __is_offer_type(self,packet):

        if packet is None:
#            print('    ... got no reply.')
            return False

        if not packet.haslayer(BOOTP):
            print('    ... is not BOOTP !!')
            return False

        if packet[BOOTP].op != 2:   # BOOTREPLY
            print('    ... is not BOOTREPLY !!')
            return False

        if packet[BOOTP].xid != self.xid:
            print('    ... has wrong xid: %d <> %d !!' % (packet[BOOTP].xid,self.xid))
            return False

        if not packet.haslayer(DHCP):
            print('    ... is not DHCP !!')
            return False

#        print(packet[DHCP].options)

        for x in packet[DHCP].options:
            if x == ('message-type',2):
                return True

        print('    ... invalid DHCP packet !!')
        return False



    #==============================================================================
    # public function "CheckDhcp"
    #
    #     Check DHCP-Server on srv_ip via dhcp_iface
    #
    #==============================================================================
    def CheckDhcp(self, dhcp_iface, srv_ip):

#        print('Starting DHCP-Check on IF = %s to Server = %s...' % (dhcp_iface, srv_ip))

        offered_address = None
        dhcp_request    = self.__craft_discover_request(dhcp_iface)
        srv_mac         = self.__get_mac_of_ip(dhcp_iface,srv_ip)
        LoopCount       = 0

        self.__sniff_start(dhcp_iface,srv_ip)

        while self.sniffer.is_alive() and self.reply_packet is None:
            if LoopCount % 10 == 0:
#                print('    ... sending DHCP-Request to %s ...' % (srv_mac))
                sendp(Ether(dst=srv_mac) / dhcp_request, verbose=False)

            LoopCount += 1
            time.sleep(0.1)

        if self.__is_offer_type(self.reply_packet):
            offered_address = self.reply_packet[BOOTP].yiaddr
            offered_gateway = self.reply_packet[BOOTP].giaddr
            print('    %s from %s' % (offered_address, offered_gateway))

        return offered_address
