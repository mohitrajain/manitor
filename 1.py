from scapy.all import *

def get_frequency(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freq_string = struct.pack("<h", freq)

    return freq_string

def get_radiotap_header(ch,drate):
    radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00' + struct.pack("<h", 2*drate)[0] + get_frequency(ch) + '\xc0\x00\xc0\x01\x00\x00')
    return radiotap_packet

iface = 'wlp0s29u1u2mon'

pkt = get_radiotap_header(5,6)
pkt = pkt / Dot11(addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = 'aa:aa:aa:aa:aa:aa', addr3 = 'aa:aa:aa:aa:aa:aa') /Dot11Beacon(cap = 0x1104) / Dot11Elt( ID=0, info = 'cddrd') / Dot11Elt (ID=1, info = "\x82\x84\x8b\x96\x24\x30\x48\x6c") / Dot11Elt (ID=3, info = "\x0b") / Dot11Elt (ID=5, info = "\x00\x01\x00\x00" )
sendp(pkt, iface = iface, count = 2, inter = .2)

pkt = get_radiotap_header(5,36)
pkt = pkt / Dot11(addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = 'aa:aa:aa:aa:aa:aa', addr3 = 'aa:aa:aa:aa:aa:aa') /Dot11Beacon(cap = 0x1104) / Dot11Elt( ID=0, info = 'c1dr6') / Dot11Elt (ID=1, info = "\x82\x84\x8b\x96\x24\x30\x48\x6c") / Dot11Elt (ID=3, info = "\x0b") / Dot11Elt (ID=5, info = "\x00\x01\x00\x00" )
sendp(pkt, iface = iface, count = 2, inter = .2)

pkt = get_radiotap_header(5,6)
pkt = pkt / Dot11(addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = 'aa:aa:aa:aa:aa:aa', addr3 = 'aa:aa:aa:aa:aa:aa') /Dot11Beacon(cap = 0x1104) / Dot11Elt( ID=0, info = 'cddrd') / Dot11Elt (ID=1, info = "\x82\x84\x8b\x96\x24\x30\x48\x6c") / Dot11Elt (ID=3, info = "\x0b") / Dot11Elt (ID=5, info = "\x00\x01\x00\x00" )
sendp(pkt, iface = iface, count = 2, inter = .2)

pkt = get_radiotap_header(5,36)
pkt = pkt / Dot11(addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = 'aa:aa:aa:aa:aa:aa', addr3 = 'aa:aa:aa:aa:aa:aa') /Dot11Beacon(cap = 0x1104) / Dot11Elt( ID=0, info = 'c6dr36') / Dot11Elt (ID=1, info = "\x82\x84\x8b\x96\x24\x30\x48\x6c") / Dot11Elt (ID=3, info = "\x0b") / Dot11Elt (ID=5, info = "\x00\x01\x00\x00" )
sendp(pkt, iface = iface, count = 2, inter = .2)
