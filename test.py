#!/bin/python

import nfqueue
from scapy.all import *
import os

# inserting iptables command here
os.system('iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1')

def callback(payload):
    data = payload.get_data()
    pkt = IP(data)
    print repr(pkt)
    if pkt.haslayer(TCP):  # Beginning modifications
        pass
        pkt[IP].dst = '10.0.0.100'
        pkt[TCP].dport = 80
        del pkt[TCP].chksum
        del pkt[IP].len
        del pkt[IP].chksum
        pkt = pkt.__class__(str(pkt))
        print repr(pkt)
    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

def main():
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(1)
    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        # removing rule
        os.system('iptables -t filter -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1')

main()
