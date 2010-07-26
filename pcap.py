import dpkt
from pcaputil import *
from socket import inet_ntoa
from tcppacket import TCPPacket
from tcpflow import TCPFlow

class TCPFlowAccumulator:
    '''Takes a list of TCP packets and organizes them into distinct
    connections, or flows. It does this by organizing packets into a
    dictionary indexed by their socket, or the tuple
    ((srcip, sport), (dstip,dport)), possibly the other way around.'''
    def __init__(self, pcap_reader):
        '''scans the pcap_reader for TCP packets, and incorporates them
        into its dictionary. pcap_reader is expected to be a dpkt.pcap.Reader'''
        self.raw_flowdict = {} # {socket: [TCPPacket]}
        for pkt in pcap_reader:
            # parse packet
            eth = dpkt.ethernet.Ethernet(pkt[1])
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    # then it's a TCP packet
                    tcp = ip.data
                    # process it
                    tcppkt = TCPPacket(pkt[0], pkt[1], eth, ip, tcp)
                    self.process_packet(tcppkt) # organize by socket
        # use TCPFlow class to stitch packets
        self.flowdict = {} # {socket: TCPFlow}
        for sock, flow in self.raw_flowdict.iteritems():
            #print 'flowing socket: ', friendly_socket(sock), flow
            self.flowdict[sock] = TCPFlow(flow)
            
    def process_packet(self, pkt):
        '''adds the tcp packet to flowdict. pkt is a TCPPacket'''
        #try both orderings of src/dst socket components
        #otherwise, start a new list for that socket
        src, dst = pkt.socket
        #ok, NOW add it
        #print 'processing packet: ', pkt
        if (src, dst) in self.raw_flowdict:
            #print '  adding as ', (src, dst)
            self.raw_flowdict[(src,dst)].append(pkt)
        elif (dst, src) in self.raw_flowdict:
            #print '  adding as ', (dst, src)
            self.raw_flowdict[(dst, src)].append(pkt)
        else:
            #print '  making new dict entry as ', (src, dst)
            self.raw_flowdict[(src,dst)] = [pkt]
    def flows(self):
        '''lists available flows by socket'''
        return [friendly_socket(s) for s in self.flowdict.keys()]


def viewtcp(pkts):
    '''prints tcp packets in the passed packets
    
    packets should be in the format returned by dpkt.pcap.Reader.__iter__'''
    for pkt in pkts:
        eth = dpkt.ethernet.Ethernet(pkt[1])
        try:
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    #now parse tcp packets
                    socket = ((inet_ntoa(ip.src), tcp.sport), (inet_ntoa(ip.dst), tcp.dport))
                    #print timestamp, socket, TCP
                    print (pkt[0], socket)
                    print '    seq =', tcp.seq
                    print '    ack =', tcp.ack
                    print '    flags =',friendly_tcp_flags(tcp.flags),' (', tcp.flags, ')'
                    print '    data =',tcp.data[:200], '\''
        except Exception as e:
            print 'Error: ', type(e), ', ', e
