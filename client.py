#!/usr/bin/python
from scapy.all import *
import pktHandler
import syscmds
from time import time, sleep
import constants
import dhcpclient

class Client(object):
    """CLass that defines Client"""
    def __init__(self,iface):
        self.iface = iface
        pass

    # run function starts the sta and begin the state transaction
    def run(self):
        if syscmds.checkmon(self.iface) == True:
            if not hasattr(self,'pktHandler'):
                self.setConf()

            self.sniffer = pktHandler.sniffer(self.iface,self.pktHandler.callback,self.pktHandler.bpfFilter)
            self.sniffer.start()
            # waiting for sniffing to start
            sleep(1)

            #self.pktHandler.apFinder()
            pass
        else:
            print 'Interface is not in monitor mode'    

    def setConf(self,ssid='NIT-WIFI',mac='aa:aa:aa:aa:aa:aa',ch=1,drate=0.5):
        self.pktHandler = pktHandler.pktHandler()
        self.pktHandler.ch = ch
        self.pktHandler.ssid = ssid
        self.pktHandler.drate = drate
        self.pktHandler.mac = mac
        self.pktHandler.iface = self.iface
        syscmds.setch(self.iface,self.pktHandler.ch)
        pass

    # this function passes packets from dhcpclient(802.3) to pkthandler(802.11) to send to ap 
    def dhcp(self):
        self.dhcpclient = dhcpclient.dhcpClient()
        pkt = self.dhcpclient.discover(self.mac)
        self.pktHandler.pkts.insert(0,pkt)
        self.pktHandler.clearQueue()
        pass


c = Client('wlp6s0mon')
c.run()
c.pktHandler.apFinder()
#c.pktHandler.bssid = '70:e4:22:c0:1a:01'
#c.pktHandler.ch = 1
#c.pktHandler.bssid = '70:e4:22:92:d9:41'
#.pktHandler.ch = 6
#syscmds.setch(c.iface,c.pktHandler.ch)
c.pktHandler.drate = 5.5
c.pktHandler.auth_request()
c.pktHandler.state = 1
c.pktHandler.step = 0
print constants.STATES[c.pktHandler.state],constants.STEPS[c.pktHandler.state][c.pktHandler.step]
#c.pktHandler.deauth()