import dpkt
from pcaputil import *

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
        return 'TCPPacket(%s, %s, %s)' % (friendly_socket(self.socket), friendly_tcp_flags(self.tcp.flags), self.tcp.data[0:60])
    def overlaps(self, other):
        return (self.start_seq <= other.start_seq and \
                other.start_seq < self.end_seq) \
                              or \
               (self.start_seq < other.end_seq and \
                other.end_seq <= self.end_seq)

