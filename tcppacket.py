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
        self.seq = tcp.seq
        self.ack = tcp.ack
        self.flags = tcp.flags

        self.seq_start = self.tcp.seq
        self.seq_end = self.tcp.seq + len(self.tcp.data) # - 1
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
        return 'TCPPacket(%s, %s, seq=%x , ack=%x, data="%s")' % (
            friendly_socket(self.socket),
            friendly_tcp_flags(self.tcp.flags),
            self.tcp.seq,
            self.tcp.ack,
            friendly_data(self.tcp.data)[:60]
        )
    def overlaps(self, other):
        return (self.seq_start <= other.seq_start and \
                other.seq_start < self.seq_end) \
                              or \
               (self.seq_start < other.seq_end and \
                other.seq_end <= self.seq_end)

