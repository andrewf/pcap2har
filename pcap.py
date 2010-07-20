import dpkt
#from dpkt.tcp import * # import all TH_* constants
from socket import inet_ntoa

class TCPFlowAccumulator:
    '''Takes a list of TCP packets and organizes them into distinct
    connections, or flows. It does this by organizing packets into a
    dictionary indexed by their socket, or the tuple
    ((srcip, sport), (dstip,dport)), possibly the other way around.'''
    def __init__(self, pcap_reader):
        '''scans the pcap_reader for TCP packets, and incorporates them
        into its dictionary. pcap_reader is expected to be a dpkt.pcap.Reader'''
        #iterate through pcap_reader
            #filter out non-tcp packets
                #organize by socket
        for pkt in pcap_reader:
            
    def process_packet(self, pkt)
        '''adds the tcp packet to flowdict. pkt is the IP part of the packet'''
        srcip = pkt.src
        dstip = pkt.dst
        sport = pkt.data.sport #pkt.data is a TCP
        dport = pkt.data.dport
        src = (srcip, sport)
        dst = (dstip, dport)
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