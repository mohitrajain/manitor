#!/usr/bin/python
from scapy.all import *
import constants
import syscmds
import threading,sys
from time import time, sleep

s = conf.L2socket(iface = 'wlp6s0mon')

# calling sniff function in seprate thread because sniff blocks
class sniffer(threading.Thread):
    def __init__(self,iface,callback,bpffilter):
        threading.Thread.__init__(self)
        self.iface = iface
        self.callback = callback
        self.bpffilter = bpffilter

    def run(self):
        sniff(iface=self.iface,prn=self.callback,store=0,filter=self.bpffilter)

# channel to frequency converter
def get_frequency(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freq_string = struct.pack("<h", freq)

    return freq_string

# drs function returns supported rates' set in integer form hex string 
def drs(hs):
    rlist = list()
    for i in hs:
        d = int(hexstr(i)[:2],16)
        if d > 128 :
            d = d - int(hexstr(i)[:2][0],16)*16
        if d %2 == 1:
            rlist.append(d/2 + 0.5)
        else:
            rlist.append(d/2)

    return rlist

# this function takes packet and Elt id no. and returns info for that Elt
def info(pkt,id):
    while pkt.haslayer(Dot11Elt):
        if pkt[Dot11Elt].ID == id:
            return pkt[Dot11Elt].info
        else:
            pkt = pkt.payload
    return ''

class pktHandler(object):
    """pkthandler class's object contains the info about wireless network and sends and receives packet also"""

    mutex = threading.Lock()

    state = 0
    step = 0
    ssid = False
    ch = False
    iface = ''
    data_rate = False
    mac_addr = 'aa:aa:aa:aa:aa:aa'
    BSSID = False
    router_addr = False
    sc = 0
    bpfFilter = ''
    rts = 0
    pkts = []

    def __init__(self):
        pass

    # run function that will sniff the air continuously in order to get responses from ap
    def run(self):
        sniff(iface=self.iface,prn=self.callback,store=0,filter=self.bpffilter)

    # this function will be the call back function to sniff
    def callback(self,pkt):
        if pkt.addr1 == self.mac:

            if pkt.type == constants.DOT11_TYPE_MANAGEMENT :

                tempRate = self.drate
                self.drate = int(hexstr(pkt.notdecoded[17])[:2],16)
                self.ack(pkt.addr2)
                self.drate = tempRate

                # probe response
                if pkt.subtype == constants.DOT11_SUBTYPE_PROBE_RESP:
                    #print pkt.addr1,pkt[Dot11ProbeResp].info
                    if pkt[Dot11ProbeResp].info == self.ssid:
                        #print 'here 2'
                        #self.ack(pkt.addr2)

                        # dataRates is the set of data rates supported by aps
                        dataRates = drs(info(pkt,1))
                        #print dataRates
                        # value of ssi signal in radio tap header
                        power = int(hexstr(pkt.notdecoded[-2][0])[:2],16) - 256
                        bssid = pkt.addr2
                        if bssid not in self.aps:
                            self.aps.append(bssid)
                            self.apsInfo.append((power,int(hexstr(info(pkt,3))[:2],16),dataRates))
                            #print '----------------------'
                            #print bssid,power,self.ch,dataRates

                # authentication response
                elif pkt.subtype == constants.DOT11_SUBTYPE_AUTH:

                    if self.state == 1 and self.step == 0:
                        print 'auth response for request'
                        #self.ack(pkt.addr2)

                        self.state = 1
                        self.step = 2
                        print constants.STATES[self.state],constants.STEPS[self.state][self.step]

                    if self.state == 1 and self.step == 2 :
                        self.state = 2
                        self.step = 0
                        print constants.STATES[self.state],constants.STEPS[self.state][self.step]
                        print 'assoc called'
                        self.assoc_request()

                    pass

                # association response
                elif pkt.subtype == constants.DOT11_SUBTYPE_ASSOC_RESP:
                    if self.state == 2 and self.step == 0:
                        print 'association response came for association request'
                        #self.ack(pkt.addr2)
                        self.state = 3
                        self.step = -1
                        print constants.STATES[self.state],constants.STEPS[self.state][self.step]
                        self.deauth()

                    pass

            elif pkt.type == constants.DOT11_TYPE_CONTROL:
                if pkt.subtype == constants.DOT11_SUTYPE_CTS:
                    self.mutex.acquire()
                    if self.rts == 1:
                        self.clearQueue()
                        self.rts = 0
                    self.mutex.release()
                    pass
                else:
                    print '======================control============================='
                    print repr(pkt)
                    print '=========================================================='

    # creating probe request with three Elt ssid , supported rates , current channel
    def probe_request(self):
        pkt = RadioTap() \
        		/ Dot11( type = 0, subtype = 4, addr1 = constants.Broadcast , addr2 = self.mac, addr3 = constants.Broadcast,SC=self.next_sc()) \
				/ Dot11ProbeReq() \
				/ Dot11Elt(ID=0, info = self.ssid) \
				/ Dot11Elt(ID=1, info = "\x02\x04\x0b\x16") \
				/ Dot11Elt(ID=3, info = struct.pack("<h",self.ch)[0])

        print int(hexstr(info(pkt,3))[:2],16)
        s.send(pkt)

    def apFinder(self):
        # setting first state
        self.state = 0
        self.step = 0
        print constants.STATES[self.state],constants.STEPS[self.state][self.state]

        self.aps = list()
        self.apsInfo = list()
        tempch = self.ch

        for i in range(1,13):
            self.ch = i
            syscmds.setch(self.iface,self.ch)
            self.probe_request()
            self.probe_request()
            sleep(1.5)

        #sleep(6)
        maxRate = -100
        x = -1
        
        if self.state == 0 and self.step == 0:
            self.state = 0
            self.step = 1
            print constants.STATES[self.state],constants.STEPS[self.state][self.state]
        

        self.mutex.acquire()
        if len(self.aps) == 0:
            print 'not any bssid found'
            self.mutex.release()
            return

        # choosing bssid with max power
        #self.mutex.acquire()
        for i in range(len(self.aps)):
            print self.aps[i]
            print self.apsInfo[i]
            if self.apsInfo[i][0] > maxRate:
                maxRate = self.apsInfo[i][0]
                x = i
        self.mutex.release()


        if self.state == 0 and self.state == 1:
            self.state = 1
            self.step = -1
            print constants.STATES[self.state],constants.STEPS[self.state][self.state]

        print '---------------- selected ap --------'        
        print self.aps[x]
        print self.apsInfo[x]

        # setting bssid to be used for further connection
        self.bssid = self.aps[x]
        self.apInfo = self.apsInfo[x]
        self.ch = self.apInfo[1]
        self.drate = self.apInfo[2][0]
        syscmds.setch(self.iface,self.ch)
        pass

    # creating auth request with open auth and Elt for auth mechanism (OUI)
    def auth_request(self):
        pkt = self.get_radiotap_header() \
                / Dot11( type = 0, subtype = 11, addr1 = self.bssid , addr2 = self.mac, addr3 = self.bssid,SC=self.next_sc()) \
                / Dot11Auth(algo=0,status=0,seqnum=1) \
                / Dot11Elt(ID=221,len=9,info='\x00\x10\x18\x02\x00\x10\x00\x00\x00')

        print repr(pkt)
        s.send(pkt)

    # association packet
    def assoc_request(self):
        pkt = self.get_radiotap_header() \
                / Dot11(type = 0, subtype=0,addr1= self.bssid , addr2=self.mac ,addr3 = self.bssid , SC=self.next_sc()) \
                / Dot11AssoReq(cap=8452,listen_interval=10) \
                / Dot11Elt(ID=0,info=self.ssid) \
                / Dot11Elt(ID=1,info='\x8b\x16\x18$0H`l')

        print repr(pkt)
        s.send(pkt)

    # acknowlegement packet :- control packet
    def ack(self,mac):
        pkt = self.get_radiotap_header() \
                / Dot11(subtype=13,type=1,addr1=mac,ID=24576)

        #self.rts = 1
        print repr(pkt)
        s.send(pkt)
        print 'ack sent'

    # sending deauth to ap , Reason code: Deauthenticated because sending STA is leaving (or has left) IBSS or ESS (0x0003)
    def deauth(self):
        pkt = self.get_radiotap_header() \
                / Dot11(subtype=12,type=0,addr1=self.bssid,addr2=self.mac,addr3=self.bssid,SC=self.next_sc()) \
                / Dot11Deauth(reason=3)

        print repr(pkt)
        s.send(pkt)

    # sending rts before transmitting data
    def rts(self):
        pkt = self.get_radiotap_header() \
                / Dot11(subtype=11,type=1,addr1=self.bssid,addr2=self.mac,SC=next_sc())

        print repr(pkt)
        s.send(pkt)

    def clearQueue(self):
        if len(self.pkts):
            #here
            pass
        pass

    # Returns radio tap header that will tell wireless card what data rate and channel to use for this particular packet
    def get_radiotap_header(self):
        print self.drate
        radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00' + struct.pack("<h",self.drate*2)[0] + get_frequency(self.ch) + '\xc0\x00\xc0\x01\x00\x00')
        return radiotap_packet

    # This function takes care of sequence number in Dot11 packet
    def next_sc(self):
        self.mutex.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.mutex.release()
        return temp * 16  # Fragment number -> right 4 bits