from .. import settings
from .. import tls
from ..tls import session
import flow as tcp
import logging


class FlowBuilder(object):
    '''
    Builds and stores tcp.Flow's from packets.

    Takes a series of tcp.Packet's and sorts them into the correct tcp.Flow's
    based on their socket. Exposes them in a dictionary keyed by socket. Call
    .add(pkt) for each packet. This will find the right tcp.Flow in the dict and
    call .add() on it. This class should be renamed.

    Members:
    flowdict = {socket: [tcp.Flow]}
    '''

    def __init__(self, tls_session_manager=None):
        self.flowdict = {}
        self.tls_session_manager = tls_session_manager or session.SessionManager(None)

    def add(self, pkt):
        '''
        filters out unhandled packets, and sorts the remainder into the correct
        flow
        '''
        #shortcut vars
        src, dst = pkt.socket
        srcip, srcport = src
        dstip, dstport = dst
        # filter out weird packets, LSONG
        if srcport == 5223 or dstport == 5223:
            logging.warning('hpvirtgrp packets are ignored')
            return
        if srcport == 5228 or dstport == 5228:
            logging.warning('hpvroom packets are ignored')
            return
#        if 38861 not in (srcport, dstport):
#            return
        # sort the packet into a tcp.Flow in flowdict. If NewFlowError is
        # raised, the existing flow doesn't want any more packets, so we
        # should start a new flow.
        if (src, dst) in self.flowdict:
            try:
                self.flowdict[(src, dst)][-1].add(pkt)
            except tcp.NewFlowError:
                self.new_flow((src, dst), pkt)
        elif (dst, src) in self.flowdict:
            try:
                self.flowdict[(dst, src)][-1].add(pkt)
            except tcp.NewFlowError:
                self.new_flow((dst, src), pkt)
        else:
            self.new_flow((src, dst), pkt)

    def new_flow(self, socket, packet):
        '''
        Adds a new flow to flowdict for socket, and adds the packet.

        Socket must either be present in flowdict or missing entirely, eg., if
        you pass in (src, dst), (dst, src) should not be present.

        Args:
        * socket: ((ip, port), (ip, port))
        * packet: tcp.Packet
        '''
        newflow = tcp.Flow()
        srcport = socket[0][1]
        dstport = socket[1][1]
        # wrap flows on port 443 in a tls.Flow
        if (srcport == 443 or dstport == 443) and settings.process_tls:
            newflow = tls.Flow(newflow, self.tls_session_manager)
        newflow.add(packet)
        if socket in self.flowdict:
            self.flowdict[socket].append(newflow)
        else:
            self.flowdict[socket] = [newflow]

    def flows(self):
        '''
        Generator that iterates over all flows.
        '''
        for flowlist in self.flowdict.itervalues():
            for flow in flowlist:
                yield flow

    def finish(self):
        map(lambda f: f.finish(), self.flows())
