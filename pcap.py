import dpkt
#from dpkt.tcp import * # import all TH_* constants
from socket import inet_ntoa

class TCPPacket(object):
    '''copied from pyper, with additions. represents a TCP packet. contains
    socket, timestamp, and data'''
    def __init__(self, ts, buf, eth, ip, tcp):
        '''ts = timestamp
        buf = original packet data
        eth = dpkt.ethernet.Ethernet that the packet came from
        ip  = dpkt.ip.IP that the packet came from
        tcp = dpkt.tcp.TCP that the packet came from
        '''
        self.ts = ts
        self.buf = buf
        self.eth = eth
        self.ip = ip
        self.tcp = tcp
        self.socket = ((self.ip.src, self.tcp.sport),(self.ip.dst, self.tcp.dport))
        self.data = tcp.data
        self.is_rexmit = None
        self.is_out_of_order = None

        self.start_seq = self.tcp.seq
        self.end_seq = self.tcp.seq + len(self.tcp.data) - 1
        self.rtt = None
    def __cmp__(self, other):
        return cmp(self.ts, other.ts)
    def __eq__(self, other):
        return not self.__ne__(other)
    def __ne__(self, other):
        if isinstance(other, TCPPacket):
            return cmp(self, other) != 0
        else:
            return True
    def __repr__(self):
        
    def overlaps(self, other):
        return (self.start_seq <= other.start_seq and \
                other.start_seq < self.end_seq) \
                              or \
               (self.start_seq < other.end_seq and \
                other.end_seq <= self.end_seq)

class TCPFlowAccumulator:
    '''Takes a list of TCP packets and organizes them into distinct
    connections, or flows. It does this by organizing packets into a
    dictionary indexed by their socket, or the tuple
    ((srcip, sport), (dstip,dport)), possibly the other way around.'''
    def __init__(self, pcap_reader):
        '''scans the pcap_reader for TCP packets, and incorporates them
        into its dictionary. pcap_reader is expected to be a dpkt.pcap.Reader'''
        self.flowdict = {} # {socket: [TCPPacket]}
        #iterate through pcap_reader
            #filter out non-tcp packets
                #organize by socket
        for pkt in pcap_reader:
            #parse packet
            eth = dpkt.ethernet.Ethernet(pkt[1])
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    #then it's a TCP packet
                    tcp = ip.data
                    #process it
                    tcppkt = TCPPacket(pkt[0], pkt[1], eth, ip, tcp)
                    self.process_packet(tcppkt)
            
    def process_packet(self, pkt):
        '''adds the tcp packet to flowdict. pkt is a TCPPacket'''
        src, dst = pkt.socket
        #ok, NOW add it
        #try both orderings of src/dst socket components
        #otherwise, start a new list for that socket
        if (src, dst) in self.flowdict:
            self.flowdict[(src,dst)].append(pkt)
        elif (dst, src) in self.flowdict:
            self.flowdict[(dst,src)].append(pkt)
        else:
            self.flowdict[(src,dst)] = [pkt]
    #



def friendly_tcp_flags(flags):
    '''returns a string containing a user-friendly representation of the tcp flags'''
    d = {dpkt.tcp.TH_FIN:'FIN', dpkt.tcp.TH_SYN:'SYN', dpkt.tcp.TH_RST:'RST', dpkt.tcp.TH_PUSH:'PUSH', dpkt.tcp.TH_ACK:'ACK', dpkt.tcp.TH_URG:'URG', dpkt.tcp.TH_ECE:'ECE', dpkt.tcp.TH_CWR:'CWR'}
    #make a list of the flags that are activated
    active_flags = filter(lambda t: t[0] & flags, d.iteritems()) #iteritems (sortof) returns a list of tuples
    #join all their string representations with '|'
    return '|'.join(t[1] for t in active_flags)

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
