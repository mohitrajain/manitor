#!/usr/bin/python

from scapy.all import *
import subprocess

# executes the command and returns the output
def execute_out(cmd):
    Command = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    (out, err) = Command.communicate()
    if err:
        logger('Error Executing ' + cmd + ' \n' + err)
    return out

# converts a mac address string into hexadecimal equivalent
def mac_to_bytes(mac):
    return ''.join(chr(int(x, 16)) for x in mac.split(':'))

# returns mac address of specified ethernet device
def find_mac(dev):
    return execute_out('ip address show dev '+ dev + " | grep ether | cut -d ' ' -f 6")

class dhcpClient(object):
    """docstring for dhcpClient"""

    def __init__(self, arg):
        self.arg = arg

    # broadcasting dhcp discover message
    def discover(self,mac):
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff',src=mac,type=2048) \
	       / IP(src='0.0.0.0',dst='255.255.255.255') \
	       / UDP(sport=68,dport=67) \
	       / BOOTP(op=1,htype=1,xid=55,ciaddr='0.0.0.0',yiaddr='0.0.0.0',siaddr='0.0.0.0',giaddr='0.0.0.0',chaddr=mac_to_bytes(mac),options='c\x82Sc') \
	       / DHCP(options=[('message-type', 1), ('param_req_list', '\x01\x1c\x02y\x0f\x06\x0c()*\x1aw\x03y\xf9!\xfc*'), ('client_id', '\xff' + mac_to_bytes(mac)[2:] + '\x00\x01\x00\x01!\xf4c\x1c'+mac_to_bytes(mac)), 'end', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad'])

        #sendp(pkt,iface='wlp0s29u1u2')
        print repr(pkt)
        return pkt

#mac = find_mac('wlp0s29u1u2')
#print mac
#discover(mac)