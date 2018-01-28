#!/usr/bin/python

import nfqueue
from scapy.all import *
import os

class eth2wire(object):
    """docstring for eth2wire"""

    def __init__(self,mac,ethInt,wireInt):
        self.mac = mac
        self.ethInt = ethInt
        self.wireInt = wireInt
        pass

    # creating dummy interface and setting its properties
    def createDummy(self):
        # we will check if dummy is loaded or not
        #os.system('lsmod | grep dummy')
        #os.system('modprobe -v dummy')
        # we will check first if self.ethInt exists or not
        #os.system('ip link add ' + self.ethInt + ' type dummy')
        # creating the dummy interface and setting its mac address
        #os.system('ip link set ' + self.ethInt +  ' address ' + self.mac)
        #os.system('ip link set ' + self.ethInt  +' up')
        pass

    # firewall function set iptables rules and manages the respective firewall program
    def firewall(self):
        # we will check other firewalls like ufw,firewalld are up or not
        # starting iptables service if it exists
        #os.system('systemctl stop firewalld.service')
        #os.system('systemctl start iptables.service')
        # now comes the iptables rules
        os.system('iptables -t filter -F')
        os.system('iptables -t nat -F')
        os.system('iptables -t filter -I OUTPUT -j NFQUEUE --queue-num 1')
        pass

    # callback for nfqueue here all packet processing will happen
    def callback(self,payload):
        data = payload.get_data()
        print repr(Ether(data))
        payload.set_verdict(nfqueue.NF_DROP)

    # listen function will create a nfqueue and send packets to callback
    def listen(self):
        q=nfqueue.queue()
        q.open()
        q.bind(socket.AF_INET)
        q.set_callback(self.callback)
        q.create_queue(1)
        q.try_run()
        print 'hello'

o1 = eth2wire(ethInt='wlp0s29u1u2',wireInt='wlp6s0mon',mac='aa:aa:aa:aa:aa:aa')
#o1.createDummy()
o1.firewall()
o1.listen()