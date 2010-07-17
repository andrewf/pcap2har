import dpkt
#from dpkt.tcp import * # import all TH_* constants
from socket import inet_ntoa

class ModifiedReader(object):
    """A copy of the dpkt pcap Reader. The only change is that the iterator
    yields the pcap packet header as well, so it's possible to check the true
    frame length, among other things.
    """
    
    def __init__(self, fileobj):
        self.name = fileobj.name
        self.fd = fileobj.fileno()
        self.__f = fileobj
        buf = self.__f.read(dpkt.pcap.FileHdr.__hdr_len__)
        self.__fh = dpkt.pcap.FileHdr(buf)
        self.__ph = dpkt.pcap.PktHdr
        if self.__fh.magic == dpkt.pcap.PMUDPCT_MAGIC:
            self.__fh = dpkt.pcap.LEFileHdr(buf)
            self.__ph = dpkt.pcap.LEPktHdr
        elif self.__fh.magic != dpkt.pcap.TCPDUMP_MAGIC:
            raise ValueError, 'invalid tcpdump header'
        self.snaplen = self.__fh.snaplen
        self.dloff = dpkt.pcap.dltoff[self.__fh.linktype]
        self.filter = ''

    def fileno(self):
        return self.fd
    
    def datalink(self):
        return self.__fh.linktype
    
    def setfilter(self, value, optimize=1):
        return NotImplementedError

    def readpkts(self):
        return list(self)
    
    def dispatch(self, cnt, callback, *args):
        if cnt > 0:
            for i in range(cnt):
                ts, pkt = self.next()
                callback(ts, pkt, *args)
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)
    
    def __iter__(self):
        self.__f.seek(dpkt.pcap.FileHdr.__hdr_len__)
        while 1:
            buf = self.__f.read(dpkt.pcap.PktHdr.__hdr_len__)
            if not buf: break
            hdr = self.__ph(buf)
            buf = self.__f.read(hdr.caplen)
            yield (hdr.tv_sec + (hdr.tv_usec / 1000000.0), buf, hdr)

def parsepacket(pkt):
    '''extracts all known information from a packet, as returned by ModifiedReader ^^^
    takes a tuple of (time as float, network data, pcap packet header)
    returns a list of [time, [ip [transport header]], data]. Basically, parse as far
    as possible, then spit out the rest of the data'''
    eth = dpkt.ethernet.Ethernet(pkt[1])
    #parse IP
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        #parse TCP
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            socket = ((inet_ntoa(ip.src), tcp.sport), (inet_ntoa(ip.dst), tcp.dport))
            return pkt[0], socket, tcp.data[:200]
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            return pkt[0], 'UDP'
        else:
            return pkt[0], ip, ip.data
    else:
        return (pkt[0], 'Eth')
#

def friendly_tcp_flags(flags):
    '''returns a string containing a user-friendly representation of the tcp flags'''
    d = {dpkt.tcp.TH_FIN:'FIN', dpkt.tcp.TH_SYN:'SYN', dpkt.tcp.TH_RST:'RST', dpkt.tcp.TH_PUSH:'PUSH', dpkt.tcp.TH_ACK:'ACK', dpkt.tcp.TH_URG:'URG', dpkt.tcp.TH_ECE:'ECE', dpkt.tcp.TH_CWR:'CWR'}
    #make a list of the flags that are activated
    active_flags = filter(lambda t: t[0] & flags, d.iteritems()) #iteritems (sortof) returns a list of tuples
    return '|'.join(t[1] for t in active_flags)

def viewtcp(pkts):
    '''prints tcp packets in the passed pcap packets'''
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