import logging
import common as tcp

from dpkt.tcp import TH_SYN

from ..sortedcollection import SortedCollection
import seq # hopefully no name collisions
from direction import Direction


class NewFlowError(Exception):
    '''
    Used to signal that a new flow should be started.
    '''
    pass


class Flow(object):
    '''
    Represents TCP traffic across a given socket, ideally between a TCP
    handshake and clean connection termination.

    This class is considered to define an abstract interface which is also
    satisfied by ssl.Flow, and used by any higher-level protocols. The
    important parts of this interface are these member variables:
    * fwd: Direction
    * rev: Direction
    * handshake: [tcp.Packet]

    Members:
    * fwd, rev = tcp.Direction, both sides of the communication stream
    * socket = ((srcip, sport), (dstip, dport)). Used for checking the direction
    of packets. Taken from SYN or first packet.
    * packets = list of tcp.Packet's, all packets in the flow
    * handshake = None or (syn, synack, ack) or False. None while a handshake is
    still being searched for, False when we've given up on finding it.
    '''

    def __init__(self):
        self.fwd = Direction(self)
        self.rev = Direction(self)
        self.handshake = None
        self.socket = None
        self.packets = []

    def add(self, pkt):
        '''
        called for every packet coming in, instead of iterating through
        a list
        '''
        # maintain an invariant that packets are ordered by ts;
        # perform ordered insertion (as in insertion sort) if they're
        # not in order because sometimes libpcap writes packets out of
        # order.

        # the correct position for pkt is found by looping i from
        # len(self.packets) descending back to 0 (inclusive);
        # normally, this loop will only run for one iteration.
        for i in xrange(len(self.packets), -1, -1):
            # pkt is at the correct position if it is at the
            # beginning, or if it is >= the packet at its previous
            # position.
            if i == 0 or self.packets[i - 1].ts <= pkt.ts: break
        self.packets.insert(i, pkt)

        # look out for handshake
        # add it to the appropriate direction, if we've found or given up on
        # finding handshake
        if self.handshake is not None:
            if pkt.flags == TH_SYN:
                # syn packet now probably means a new flow started on the same
                # socket. Request (demand?) that a new flow be started.
                raise NewFlowError
            self.merge_pkt(pkt)
        else: # if handshake is None, we're still looking for a handshake
            if len(self.packets) > 13: # or something like that
                # give up
                self.handshake = False
                self.socket = self.packets[0].socket
                self.flush_packets() # merge all stored packets
            # check last three packets
            elif tcp.detect_handshake(self.packets[-3:]):
                # function handles packets < 3 case
                self.handshake = tuple(self.packets[-3:])
                self.socket = self.handshake[0].socket
                self.flush_packets()

    def flush_packets(self):
        '''
        Flush packet buffer by merging all packets into either fwd or rev.
        '''
        for p in self.packets:
            self.merge_pkt(p)

    def merge_pkt(self, pkt):
        '''
        Merges the packet into either the forward or reverse stream, depending
        on its direction.
        '''
        if self.samedir(pkt):
            self.fwd.add(pkt)
        else:
            self.rev.add(pkt)

    def finish(self):
        '''
        Notifies the flow that there are no more packets. This finalizes the
        handshake and socket, flushes any built-up packets, and calls finish on
        fwd and rev.
        '''
        # handle the case where no handshake was detected
        if self.handshake is None:
            self.handshake = False
            self.socket = self.packets[0].socket
            self.flush_packets()
        self.fwd.finish()
        self.rev.finish()

    def samedir(self, pkt):
        '''
        returns whether the passed packet is in the same direction as the
        assumed direction of the flow, which is either that of the SYN or the
        first packet. Raises RuntimeError if self.socket is None
        '''
        if not self.socket:
            raise RuntimeError(
                'called tcp.Flow.samedir before direction is determined')
        src, dst = pkt.socket
        if self.socket == (src, dst):
            return True
        elif self.socket == (dst, src):
            return False
        else:
            raise ValueError(
                'tcp.Flow.samedir found a packet from the wrong flow')

    def writeout_data(self, basename):
        '''
        writes out the data in the flows to two files named basename-fwd.dat and
        basename-rev.dat.
        '''
        with open(basename + '-fwd.dat', 'wb') as f:
            f.write(self.fwd.data)
        with open(basename + '-rev.dat', 'wb') as f:
            f.write(self.rev.data)
