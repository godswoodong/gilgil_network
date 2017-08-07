import  optparse, socket, time, binascii
from struct import *

ETH_P_ALL = 3
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))


def seperate_packet(packet):
    packet2 = packet[0:34]
    iphdr = unpack('!6s6sHBBHHHBBH4s4s' , packet2)
    dmac = binascii.hexlify(str(iphdr[0])).decode()
    smac = binascii.hexlify(str(iphdr[1])).decode()
    eth_type=hex(iphdr[2])
    version_ihl = iphdr[3]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iphdr_length = ihl * 4
    ttl = iphdr[8]
    protocol = iphdr[9]
    s_addr = socket.inet_ntoa(iphdr[11]);
    d_addr = socket.inet_ntoa(iphdr[12]);
    print('---------------------------------------------------------------------------------------------')
    print("DMAC : " + str(dmac) + "  SMAC : " + str(smac) + "  EthernetType : " +str(eth_type))
    print('---------------------------------------------------------------------------------------------')
    print( 'Version : ' + str(version) + ' IP Header Length : ' +\
    str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) +\
    ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

    tcp_header = packet[iphdr_length:iphdr_length+20]
    tcphdr = unpack('!HHLLBBHHH' , tcp_header)

    source_port = tcphdr[0]
    dest_port = tcphdr[1]
    sequence = tcphdr[2]
    acknowledgement = tcphdr[3]
    doff_reserved = tcphdr[4]
    tcphdr_length = doff_reserved >> 4
    print('---------------------------------------------------------------------------------------------')
    print( 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) +\
    ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) +\
    ' TCP header length : ' + str(tcphdr_length))

    h_size = iphdr_length + tcphdr_length * 4
    data_size = len(packet) - h_size
    data = packet[h_size:]

    print ('Data : ' + data)

while True:
        try:
		packet = sock.recv(65535)
		seperate_packet(packet)
	except socket.error:
		print('error')
