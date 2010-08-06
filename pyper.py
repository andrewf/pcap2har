#!/usr/bin/env python

import sys

from dpkt.ethernet import *
from dpkt.ip import *
from dpkt.tcp import *
from dpkt.udp import *
from dpkt.dns import *
from dpkt.http import *
import dpkt
import logging
import urllib
from re import compile as re
from itertools import chain
import xml.sax
import xml.sax.handler
from socket import *
from pprint import pformat
from struct import unpack
from traceback import format_exc
import traceback
import tempfile
from pcaputil import *

VERSION = 12

log = logging.getLogger(__file__)
log.setLevel(logging.CRITICAL)
log.addHandler(logging.StreamHandler())

def safe_reduction(
    list, 
    selector = lambda x: x, 
    condition = lambda x: x is not None,
    reduction = sum
):
    """
    A function to safely apply a reduction function (min, max average, etc)
    to a list of values that may include bad data (some of the values are
    None, for example). 
    
    You can supply a selector function that extracts the value out of the
    item, a condition function which decides whether or not to include
    this item in the reduction, and the reduction function itself, which is
    any function that takes a sequence and reduces it to another value.

    Returns None if no items passed the condition.
    """
    safe_list = [
        selector(x) for x in list
        if condition(selector(x))
    ]
    if len(safe_list):
        return reduction(safe_list)
    else:
        return None

def safe_average(
    list, 
    selector = lambda x: x,
    condition = lambda x: x is not None,
):
    return safe_reduction(
        list, 
        selector, 
        condition,
        reduction = lambda l: sum(l) / float(len(l))
    )

def safe_min(
    list, 
    selector = lambda x: x,
    condition = lambda x: x is not None,
):
    return safe_reduction(list, selector, condition, min)

def safe_max(
    list, 
    selector = lambda x: x,
    condition = lambda x: x is not None,
):
    return safe_reduction(list, selector, condition, max)

def safe_sum(
    list, 
    selector = lambda x: x,
    condition = lambda x: x is not None,
):
    return safe_reduction(list, selector, condition, sum)


class NoFlowsError(Exception):
    pass

def flow_str(socket):
    s, d = socket
    src, sport = s
    dst, dport = d
    return '%s:%d -> %s:%d' % (
        inet_ntoa(src), sport,
        inet_ntoa(dst), dport
    )

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


class Flow(object):
    def __init__(self, socket, analysis, index, packets):

        # Save params
        self.socket = socket
        self.analysis = analysis
        self.index = index
        self.orig_index = index
        self.packets = packets

        # Unpack socket
        s, d = socket
        sip, self.sport = s
        dip, self.dport = d
        self.sip = inet_ntoa(sip)
        self.dip = inet_ntoa(dip)
        self.hostname = '('+self.dip+')'

        # Time analysis
        self.start = min(p.ts for p in self.packets)
        self.end = max(p.ts for p in self.packets)
        self.duration = self.end - self.start

        self.analyze()

    @property
    def real_flow(self):
        return self

    def analyze(self):
        """
        Subclasses should override this to do post __init__()
        processing without having to override __init__().
        """
        pass

    relative_start = property(
        lambda self: self.start - self.analysis.global_start)
    relative_end = property(
        lambda self: self.end - self.analysis.global_start)
    http_relative_start = property(
        lambda self: self.start - self.analysis.http_start)
    http_relative_end = property(
        lambda self: self.end - self.analysis.http_start)

    def __repr__(self):
        return '%s <%s, start=%s>' % (
            self.__class__.__name__,
            flow_str(self.socket),
            self.start
        )
    def __cmp__(self, other):
        """Flows are compared based on their start time."""
        return cmp(self.start, other.start)
    def __eq__(self, other):
        return not self.__ne__(other)
    def __ne__(self, other):
        if isinstance(other, Flow):
            return self.__cmp__(other) != 0
        else:
            return True

    def host(self):
        """
        Returns the highest level hostname this flow could belong to, given
        that there is dns information available in the parent.
        """
        if self.dip in self.analysis.dns.chains:
            return self.analysis.dns.chains[self.dip][-1]
        else:
            return self.dip
    def host_chain(self):
        if self.dip in self.analysis.dns.chains:
            return reversed(self.analysis.dns.chains[self.dip])
        else:
            return []


class TCPFlow(Flow):

    def __repr__(self):
        return '%s <%s, fwd=%s, rev=%s>' % (
            self.__class__.__name__,
            flow_str(self.socket),
            friendly_data(self.forward_data)[:60],
            friendly_data(self.reverse_data)[:60]
        )
    def analyze(self):

        def assemble_stream(packets, seq_start):
            # Assembles a data stream given a list of packets all in the same
            # direction. These packets should be partially sorted.
            # NOTE: this fills the self.retransmission

            ### DEBUG ###
            stream = ''
            packets = [x for x in packets]
            raw_list = [
                (
                    # Range covered by this packet
                    (pkt.tcp.seq, pkt.tcp.seq + len(pkt.tcp.data) - 1),
                ) for pkt in packets
            ]
            raw_list.sort()
            #log.debug('RAW_LIST: \n%s' % pformat(raw_list))
            #### DEBUG ###

            # Get a list of the data packets in sequence.  (Remember, these are normalized seqs)
            sequence_list = [
                (
                    # Range covered by this packet
                    (pkt.tcp.seq, pkt.tcp.seq + len(pkt.tcp.data) - 1),
                    # Reference to the packet
                    pkt
                ) for pkt in packets if \
                    len(pkt.tcp.data) != 0 and \
                    (not pkt.tcp.flags & TH_SYN) and \
                    #(not pkt.tcp.flags & TH_FIN) and \ # No, fin can has data
                    (not pkt.tcp.flags & TH_RST)
            ]
            sequence_list.sort(key = lambda x: x[0][0])
            #log.debug('SEQUENCE_LIST %s: \n%s' % (flow_str(self.socket), pformat(sequence_list)))
            #log.debug('SEQ_START: \n%d' % seq_start)

            ## Now assemble the stream from the sequence list
            if self.syn:
                # SYN counts as one byte if that's where we got initial seq
                cur_seq = seq_start + 1
            elif len(sequence_list): 
                # If we started in the middle, just use the first seq we see
                (start, end), pkt = sequence_list[0]
                cur_seq = start

            segments = []
            for ((start,end),pkt) in sequence_list:

                # If this packet is in order, just add it's data and advance
                if start == cur_seq:
                    cur_seq = end + 1

                # If we got some of the data already this must be a rexmit. 
                # Since python's list.sort() is stable, we know this packet
                # came later and therefore is the retransmission.
                elif start < cur_seq:
                    # Does it have new data?
                    if end > cur_seq:
                        segments.append(pkt.tcp.data[end-cur_seq:])
                        cur_seq = end + 1
                    pkt.is_rexmit = True
                    self.rexmit_packets.append(pkt)

                # If there is a gap, the packet must be out of order. Anything
                # from here on out is a lost cause, since we sorted it, there
                # is no hope of filling the gap (this also means the flow is
                # incomplete as captured).
                else:
                    pkt.is_out_of_order = True
                    self.ooo_packets.append(pkt)
                    self.missing_data = True
                    
            #log.debug('SEGMENTS (%d): \n%s' % (len(segments), `segments`))
            #log.debug('OOO PACKETS (%d): \n%s' % (len(self.ooo_packets), `self.ooo_packets`))

            stream = ''.join(segments)
            return sequence_list, stream
        #end def assemble_stream

        class TCPSeqNormalizer(object):
            # jh:
            # I'm normalizing the sequence numbers so they're sortable.  This is
            # an attempt to ensure they have a monotonically increasing ordering
            # even if the sequence number wraps.  (and even if the packets are not
            # in order, of course)
            # It still starts at the same spot, but after a wrap, it will count as
            # 2^32 + seq, and continue from there.  (So mod by 2^32 to get the original
            # value back.)
            # once we see sequence numbers pass 0xc0000000, increase low_seq_offset by
            # the sequence number space.  This means subsequent numbers that wrap 
            # (so they're below 0x80000000 by value) will come after the current 
            # sequence number.

            # once the sequence numbers pass 0x40000000, increase high_seq_offset up to 
            # low_seq_offset, so that numbers past 0x80000000 will come after the current
            # number again. (because otherwise, they'd have the lower offset value to add)

            # this technique can fail with more than 1GB in flight.  (If you get a seq#
            # past 0xc0000000 (3g), you'll increase low_seq_offset, and if you later get 
            # a seq# under 0x80000000 (2g), you'll treat it as wrapped, and add 4g.)  It
            # might be possible to improve the tolerance to handle up to 2GB in flight.

            # PS: This technique is apparently called "unwrap" in matlab, and some call it
            # "unmod".  It's often used for handling values like degrees or radians that
            # are cyclic within a certain range and have a discontinuous jump in value, but
            # really represent some continuous property.
            # Note: You can get back the original sequence number as (seq % 0x100000000)
            def __init__(self):
                self.high_seq_offset = 0
                self.low_seq_offset = 0
                self.high_ack_offset = 0
                self.low_ack_offset = 0
            def normalize_seq(self, pkt):
                if self.low_seq_offset == self.high_seq_offset:
                    if pkt.tcp.seq >= 0xc0000000:
                        self.low_seq_offset += 0x100000000
                else:
                    if pkt.tcp.seq < 0x80000000 and pkt.tcp.seq >= 0x40000000:
                        self.high_seq_offset = self.low_seq_offset
                if pkt.tcp.seq < 0x80000000:
                    pkt.tcp.seq += self.low_seq_offset
                else:
                    pkt.tcp.seq += self.high_seq_offset

                # same thing for acks
                if self.low_ack_offset == self.high_ack_offset:
                    if pkt.tcp.ack >= 0xc0000000:
                        self.low_ack_offset += 0x100000000
                else:
                    if pkt.tcp.ack < 0x80000000 and pkt.tcp.ack >= 0x40000000:
                        self.high_ack_offset = self.low_ack_offset
                if pkt.tcp.ack < 0x80000000:
                    pkt.tcp.ack += self.low_ack_offset
                else:
                    pkt.tcp.ack += self.high_ack_offset

        # end class TCPSeqNormalizer

        # real begin of analyze(self)
        self.missing_data = None # True mean for sure we are missing data
        # Detect handshake
        self.has_handshake = False
        self.handshake_duration = None
        self.syn = None
        self.synack = None
        self.ack = None
        self.has_rst = False
        self.has_fin = False
        if len(self.packets) >= 3:
            # TODO: more robust handshake detection
            first, second, third = self.packets[0:3]
            if first.tcp.flags & TH_SYN and not first.tcp.flags & TH_ACK:
                self.syn = first
                if second.tcp.flags & (TH_SYN | TH_ACK):
                    self.synack = second
                    if third.tcp.flags & TH_ACK:
                        self.ack = third
                        self.has_handshake = True
                        self.handshake_duration = self.ack.ts - self.syn.ts 

        if self.has_handshake:
            seq_forward_start = self.syn.tcp.seq
            seq_reverse_start = self.synack.tcp.seq
        else:
            # TODO: what is the best way to go if the capture doesn't have
            # a handshake?
            seq_forward_start = self.packets[0].tcp.seq
            seq_reverse_start = self.packets[0].tcp.ack  # this always work?
            # Try finding the first packet in the opposite direction
            for pkt in self.packets:
                if not self.samedir(pkt):
                    seq_reverse_start = pkt.tcp.seq
                    break

        self.rexmit_packets = []
        self.ooo_packets = []

        for pkt in self.packets:
            self.has_rst |= ((pkt.tcp.flags & TH_RST) != 0)
            self.has_fin |= ((pkt.tcp.flags & TH_FIN) != 0)
        self.open = (not self.has_rst) and (not self.has_fin)

        fwd_pkts = [pkt for pkt in self.packets if self.samedir(pkt)]
        rev_pkts = [pkt for pkt in self.packets if not self.samedir(pkt)]

        # un-mod sequence numbers (let them exceed 2^32 instead of wrapping)
        norm =  TCPSeqNormalizer()
        for pkt in fwd_pkts:
            norm.normalize_seq(pkt)
        norm =  TCPSeqNormalizer()
        for pkt in rev_pkts:
            norm.normalize_seq(pkt)

        #log.debug('LOCALS \n%s' % pformat(self.__dict__))
        # Grab forward stream
        self.forward_sequence_list, self.forward_data = \
            assemble_stream(fwd_pkts, seq_forward_start)
        self.forward_sequence_start = self.forward_sequence_list[0][0][0] \
             if len(self.forward_sequence_list) else None

        # And reverse stream
        self.reverse_sequence_list, self.reverse_data = \
            assemble_stream(rev_pkts, seq_reverse_start)
        self.reverse_sequence_start = self.reverse_sequence_list[0][0][0] \
             if len(self.reverse_sequence_list) else None

        #log.debug('FORWARD DATA: \n%s' % `self.forward_data`)
        #log.debug('REVERSE DATA: \n%s' % `self.reverse_data`)

        # Calculate RTT
        def calculate_rtt(samedir=True):
            #log.debug('\n\nCALCULATING RTT: samedir = %s\n' % str(samedir))
            # Calculate rtt for handshake
            if self.has_handshake:
                self.syn.rtt = self.synack.ts - self.syn.ts
                self.synack.rtt = self.ack.ts - self.synack.ts
            # Calculate rtt from data packets
            soq = []
            high_tx_seq = None
            for pkt in self.packets:
                #log.debug('\n\tcalculate_rtt: pkt id %u time %f' % (
                #    pkt.ip.id, pkt.ts))
                # this is a data pkt in the reverse direction
                if bool(self.samedir(pkt)) == bool(samedir):
                    #log.debug('\tsamedir pkt id %u'%pkt.ip.id)
                    if len(pkt.tcp.data) > 0:
                        # only add new pkts to soq
                        if high_tx_seq is None or \
                                pkt.end_seq > high_tx_seq:
                            #log.debug('\tadd pkt id %u'%pkt.ip.id)
                            high_tx_seq = pkt.end_seq
                            soq.append(pkt)
                        # retransmission
                        else:
                            #log.debug('\tretrans pkt id %u'%pkt.ip.id)
                            # remove any soq pkt that overlaps with pkt
                            for soq_pkt in soq:
                                if soq_pkt.overlaps(pkt):
                                    soq.remove(soq_pkt)
                # an ack
                else:
                    #log.debug('\tother dir pkt id %u'%pkt.ip.id)
                    most_recent_removal = None
                    # remove all acked soq pkts and save the last
                    for soq_pkt in soq:
                        #log.debug('\tpkt.tcp.ack %u soq_pkt.end %u >? %s'% (
                        #    pkt.tcp.ack-1, soq_pkt.end_seq,
                        #    pkt.tcp.ack-1 >= soq_pkt.end_seq))
                        if pkt.tcp.ack > soq_pkt.end_seq:
                            most_recent_removal = soq_pkt
                            soq.remove(soq_pkt)

                    if most_recent_removal is not None:
                        most_recent_removal.rtt = pkt.ts - most_recent_removal.ts
                        #log.debug(
                        #    '\tack id %u time %f data id %u time %f rtt %f' % (
                        #    pkt.ip.id, pkt.ts, most_recent_removal.ip.id, \
                        #    most_recent_removal.ts, most_recent_removal.rtt))

        calculate_rtt(samedir = True)
        calculate_rtt(samedir = False)

        # Calcualte RTT stats
        self.forward_packets = fwd_pkts
        self.reverse_packets = rev_pkts

        # AVG
        self.forward_rtt_avg = safe_average(
            self.forward_packets,
            selector = lambda pkt: pkt.rtt,
        )
        self.reverse_rtt_avg = safe_average(
            self.reverse_packets,
            selector = lambda pkt: pkt.rtt,
        )
        
        # MAX
        self.forward_rtt_max = safe_max(
            self.forward_packets,
            selector = lambda pkt: pkt.rtt,
        )
        self.reverse_rtt_max = safe_max(
            self.reverse_packets,
            selector = lambda pkt: pkt.rtt,
        )

        # MIN
        self.forward_rtt_min = safe_min(
            self.forward_packets,
            selector = lambda pkt: pkt.rtt,
        )
        self.reverse_rtt_min = safe_min(
            self.reverse_packets,
            selector = lambda pkt: pkt.rtt,
        )

        #log.debug("\tFORWARD RTT: avg %.3f max %.3f min %.3f" % (
        #    self.forward_rtt_avg, self.forward_rtt_max, self.forward_rtt_min
        #))
        #log.debug("\tREVERSE RTT: avg %.3f max %.3f min %.3f" % (
        #    self.reverse_rtt_avg, self.reverse_rtt_max, self.reverse_rtt_min
        #))

        # Totals (sum the forward and reverse values and ignore None's,
        # if both are None then the total is None)
        self.rtt_avg = safe_sum((self.forward_rtt_avg, self.reverse_rtt_avg))
        self.rtt_max = safe_sum((self.forward_rtt_max, self.reverse_rtt_max))
        self.rtt_min = safe_sum((self.forward_rtt_min, self.reverse_rtt_min))

        #log.critical("\tTOTAL RTT: avg %-10f max %-10f min %-10f" % (
        #    self.rtt_avg, self.rtt_max, self.rtt_min
        #))

        # begin calculating stalls, pauses, and availability times (by byte)
        class TCPTimer(object):
            def __init__(self, start_seq, start_ts, stall_thresh=0.5):
                self.stalls = []
                self.pauses = []
                self.availability = []

                self.hi_seq = start_seq
                self.hi_ack = start_seq
                self.last_seq = start_seq
                self.seq_advance_ts = start_ts
                self.ack_advance_ts = start_ts
                self.last_seq_ts = start_ts
                self.last_ack_ts = start_ts
                self.stall_thresh = stall_thresh

            def next_seq(self, ts, seq):
                if seq > self.hi_seq:
                    self.hi_seq = seq
                    self.seq_advance_ts = ts
                self.last_seq = seq
                self.last_seq_ts = ts

            def next_ack(self, ts, ack):
                if ack > self.hi_ack:
                    prev_ts = self.last_seq_ts

                    self.availability.append((prev_ts, self.hi_ack, ack))
                    timediff = prev_ts-self.ack_advance_ts
                    if timediff > self.stall_thresh:
                        if self.hi_seq > self.last_seq:
                            self.stalls.append((self.ack_advance_ts, prev_ts))
                        else:
                            self.pauses.append((self.ack_advance_ts, prev_ts))
                    self.ack_advance_ts = prev_ts
                    self.hi_ack = ack
        #end class TCPTimer

        if self.rtt_min is None:
            stall_thresh = 0.5
        else:
            stall_thresh = self.rtt_min*2.5
            if stall_thresh < 0.2:
                stall_thresh = 0.2
        start_time =  self.packets[0].ts
        fwdTimer = TCPTimer(seq_forward_start, start_time, stall_thresh)
        bwdTimer = TCPTimer(seq_reverse_start, start_time, stall_thresh)
        fwd_ha = seq_forward_start
        bwd_ha = seq_reverse_start
        last_ts = 0.0
        for pkt in self.packets:
            if pkt.ts < last_ts:
                print 'on %s: %f vs. %f out of order' % (self.socket, last_ts-start_time, pkt.ts-start_time)
            if self.samedir(pkt):
                fwdTimer.next_seq(pkt.ts, pkt.tcp.seq)
                bwdTimer.next_ack(pkt.ts, pkt.tcp.ack)
                if bwd_ha < pkt.tcp.ack:
                    bwd_ha = pkt.tcp.ack
            else:
                bwdTimer.next_seq(pkt.ts, pkt.tcp.seq)
                fwdTimer.next_ack(pkt.ts, pkt.tcp.ack)
                if fwd_ha < pkt.tcp.ack:
                    fwd_ha = pkt.tcp.ack

        self.forward_stalls = fwdTimer.stalls
        self.reverse_stalls = bwdTimer.stalls
        self.forward_pauses = fwdTimer.pauses
        self.reverse_pauses = bwdTimer.pauses
        self.forward_availability = fwdTimer.availability
        self.reverse_availability = bwdTimer.availability
        # end calculating stalls and availability times (by byte)


    http_relative_handshake_end = property(
        lambda self: self.ack.ts - self.analysis.http_start if self.has_handshake else None
    )

    def samedir(self, packet):
        """Returns True if the packet is in the same direction as the SYN
           (or the first packet if there is no SYN, or reverse if first src 
           port is 80 and dst port is not)."""
        # TODO: we probably should put forward/reverse values in a structure based on
        # an early guess, then swap them if we later find we got it backwards,
        # and have an easy "requests==forward, response==reverse" association.
        if self.has_handshake:
            return self.syn.tcp.sport == packet.tcp.sport
        if len(self.packets) == 0:
            return None
        if self.packets[0].tcp.sport == 80:
            # if first packet's source port is 80 (http) then we probably got it
            # backwards.
            return self.packets[0].tcp.dport == packet.tcp.sport
        return self.packets[0].tcp.sport == packet.tcp.sport

class HTTPFlow(TCPFlow):

    def analyze(self):
        super(HTTPFlow, self).analyze()

        self.requests = []
        self.responses = []
        self.pairs = []
        self.dns_query = None
        self.flow_states = []

        def gather_messages(MessageClass, start_seq, seq_list, data):
            # Returns a list of messages from a stream
            #log.debug('gathering messages')
            messages = []
            cur_seq = start_seq
            while len(data):
                #log.debug('%s len %d data %s cur_seq %d messages %s\n' %
                #        (MessageClass.__name__, len(data), `data`,cur_seq,`messages`))
                message = MessageClass(data, cur_seq, seq_list, self)
                messages.append(message)
                cur_seq += message.len
                data = message.data
            return messages

        #log.debug('PARSING HTTP')
        try:
            #log.debug(' > GUESSING FORWARD DIRECTION')
            self.requests = gather_messages(
                HTTPRequest, self.forward_sequence_start,
                self.forward_sequence_list, self.forward_data)
            self.responses = gather_messages(
                HTTPResponse, self.reverse_sequence_start,
                self.reverse_sequence_list, self.reverse_data)

            # Are the requests the same direction as the TCP flow?
            # NOTE: this does not really matter, it just keeps track of
            # which stream (forward or reverse) the http request came from.
            self.request_direction = True
            #log.debug(' CORRECT. NEW SELF: \n%s' % pformat(self.__dict__))

        except Exception, e:

            #log.debug(format_exc())

            #log.debug(' > GUESSING REVERSE DIRECTION %s' % (flow_str(self.socket)))
            self.requests = gather_messages(
                HTTPRequest, self.reverse_sequence_start,
                self.reverse_sequence_list, self.reverse_data)
            self.responses = gather_messages(
                HTTPResponse, self.forward_sequence_start,
                self.forward_sequence_list, self.forward_data)

            self.request_direction = False
            #log.debug(' CORRECT. NEW SELF: \n%s' % pformat(self.__dict__))

        # pairs?
        self.pairs = zip(self.requests, self.responses)

        if not len(self.pairs):
            raise Exception('This HTTP flow doesn\'t have enough pairs.')

        self.build_states()

        # Find duration from start of flow to the first request
        self.handshake_to_request = None
        if len(self.pairs):
            (first_req, first_resp), first_pkt = self.pairs[0], self.packets[0]
            if self.has_handshake:
                self.handshake_to_request = first_req.start - self.ack.ts
            else:
                self.handshake_to_request = first_req.start - first_pkt.ts

        self.tcp_upload = safe_sum(len(request) for request in self.requests)
        self.tcp_download = safe_sum(len(response) for response in self.responses)

        self.http_upload = sum(len(request.body) 
            for request in self.requests)
        self.http_download = sum(len(response.body) 
            for response in self.responses)

        # These are based on the the http messages, rather than raw packets.
        # The start will always include a handshake if there is one.
        self.http_start = min((request.sort_start for request in self.requests)) \
            if len(self.requests)!=0 else self.start
        self.http_end = max((response.end for response in self.responses)) \
            if len(self.responses)!=0 else self.end
        # This is potentially shorter than self.duration.
        self.http_duration = self.http_end - self.http_start

    # Converted from timestamp
    http_relative_http_start = property(
        lambda self: self.http_start - self.analysis.http_start)
    http_relative_http_end = property(
        lambda self: self.http_end - self.analysis.http_start)

    num_request_packets = property(
        lambda self: sum(len(request.packets) 
        for request, response in self.pairs))
    num_response_packets = property(
        lambda self: sum(len(response.packets) 
        for request, response in self.pairs))

    def build_states(self):
        """
        Containment function to calculate the list of flow states out of
        the information found in the flow object. It goes step-by-step
        through the stages of the flow and appends states as it goes.
        """

        # Handshake
        if self.has_handshake:
            self.flow_states.append((self.syn.ts, self.ack.ts, fs_handshake))
            if len(self.pairs) > 0:
                self.flow_states.append((self.ack.ts, self.pairs[0][0].start, fs_handshake_done))

        # Bail if we don't have any pairs
        if len(self.pairs) <= 0:
            return

        # Gather together the stalls for use later
        # (usually client starts, so reverse is response)
        self.response_stalls = self.reverse_stalls
        self.response_pauses = self.reverse_pauses
        self.response_availability = self.reverse_availability
        if not self.request_direction:
            self.response_stalls = self.forward_stalls
            self.response_pauses = self.forward_pauses
            self.response_availability = self.forward_availability

        # Loop through each request/response pair
        prev_resp = None
        for req, resp in self.pairs:

            # Idle time between pairs
            if prev_resp != None:
                self.flow_states.append((prev_resp.end, req.start, fs_idle))
            prev_resp = resp

            # 
            append_pair_states(self.flow_states, 
                req.start, req.end, 
                resp.start, resp.end, 
                req.flow.rtt_min/2
            )

            resp.stalls = [
                    (max(start, resp.start)-resp.start, min(end, resp.end)-resp.start) for start, end in self.response_stalls 
                    if (start >= resp.start and start < resp.end) or (end > resp.start and end <= resp.end)]
            resp.pauses = [
                    (max(start, resp.start)-resp.start, min(end, resp.end)-resp.start) for start, end in self.response_pauses 
                    if (start >= resp.start and start < resp.end) or (end > resp.start and end <= resp.end)]
            self.flow_states.extend([(start+resp.start, end+resp.start, fs_paused) for start, end in resp.pauses])
            #if len(resp.pauses) > 0 or len(resp.stalls) > 0:
            #    print "%s: %d pauses, %d stalls" % (req.base_uri_trunc, len(resp.pauses), len(resp.stalls))
            #    if len(resp.pauses) > 0:
            #        print "pauses: %s" % (`resp.pauses`)
            #    if len(resp.stalls) > 0:
            #        print "stalls: %s" % (`resp.stalls`)

            resp.availability = []
            initial_seq = None
            for ts, fromseq, redge in self.response_availability:
                if ts >= resp.start and ts <= resp.end:
                    if initial_seq is None:
                        initial_seq = fromseq
                    resp.availability.append((ts-resp.start, redge-initial_seq))

            # TBD: this is just bad.  availability is sometimes getting built 
            #      wrong when there's stuff like out of order packets. Hack
            #      it into shape so I can make assumptions about it:
            # 1. availability monotonically increases in offset and time
            # 2. last byte's time offset is response duration
            # 3. last byte exactly equals total length of response

            # In theory, if availability-building logic were perfect, none of
            # these would ever be hit. In practice, even if we fix the obvious
            # stuff, there might be some trouble with pipelining (2 responses
            # could be in the same packet, for instance). The right thing
            # ultimately is to make the logic solid and check the assertions,
            # but for now, we fixup anything broken after the initial pass.
            last_ts, last_off = resp.availability[0]
            idx = 1
            showed_orig = False
            while idx < len(resp.availability):
                ts, offset = resp.availability[idx]
                if ts > resp.duration or offset > resp.total_bytes or last_ts > ts or last_off >= offset:
                    if not showed_orig:
                        showed_orig = True
                        #log.debug(`resp.availability`)
                    #log.debug('fixup bad availability: %s, %f/%d comes behind %f/%d' % (req.base_uri_trunc, ts, offset, last_ts, last_off))
                    del resp.availability[idx]
                else:
                    last_ts = ts
                    last_off = offset
                    idx+=1

            if len(resp.availability) > 0:
                tail_ts, tail_off = resp.availability[-1]
                if tail_ts < resp.duration or tail_off < resp.total_bytes:

                    if not showed_orig:
                        showed_orig = True
                        #log.debug(`resp.availability`)
                    if not (tail_ts < resp.duration and tail_off < resp.total_bytes):
                        #log.debug('fixup bad availability: %s %f/%d ended earlier than response %f/%d' % (req.base_uri_trunc, tail_ts, tail_off, resp.duration, resp.total_bytes))
                        del resp.availability[-1]
                    #else:
                    #    log.debug('fixup bad availability: %s %f/%d ended completely before response %f/%d' % (req.base_uri_trunc, tail_ts, tail_off, resp.duration, resp.total_bytes))
                    resp.availability.append((resp.duration, resp.total_bytes))
            else:
                #log.debug('fixup bad availability: %s was empty' % (req.base_uri_trunc, tail_ts, tail_off, resp.duration, resp.total_bytes))
                resp.availability.append((resp.duration, resp.total_bytes))
                showed_orig = True

            #if showed_orig:
            #    log.debug(`resp.availability`)
            #    log.debug('resp start %f, end %f, dur %f, tot %d' % (resp.start, resp.end, resp.duration, resp.total_bytes))

            # these should never fire (ideally because of good logic, but currently because of the fixup above)
            assert(len(resp.availability) > 0)
            last_ts, last_off = resp.availability[0]
            for ts, offset in resp.availability[1:]:
                if last_ts > ts or last_off >= offset:
                    log.critical('bad availability: %s, %f/%d comes behind %f/%d' % (req.base_uri_trunc, ts, offset, last_ts, last_off))
                    log.critical(`resp.availability`)
                    log.critical('total: %d, start %f, end %f, dur %f' % (resp.total_bytes, resp.start, resp.end, resp.end-resp.start))
                assert(last_ts <= ts)
                assert(last_off < offset)
                last_ts = ts
                last_off = offset
            assert(resp.availability[-1][1]==resp.total_bytes)
            assert(resp.availability[-1][0]==(resp.end-resp.start))

        for start, end in self.response_stalls:
            self.flow_states.append((start, end, fs_stalled))

        regions = [(req.sort_start, resp.end) for req, resp in self.pairs]
        self.flow_durations, self.flow_colors = st.full_view()
        for (req, resp), (durations, colors) in zip(self.pairs, st.region_views()):
            req.pair_durations = durations
            req.pair_colors = colors

        #if len(self.response_stalls) > 0:
        #    log.debug("%s: stalls: %s" % (flow_str(self.socket), `self.response_stalls`))
        #    log.debug("flow_states: %s" % (`self.flow_states`))
        #    log.debug("disjoint_states: %s" % (`disjoint_states`))

class UDPFlow(Flow):
    def analyze(self):
        super(UDPFlow, self).analyze()


class TCPPacket(object):
    def __init__(self, ts, buf, eth, ip, tcp):
        self.ts = ts
        self.buf = buf
        self.eth = eth
        self.ip = ip
        self.tcp = tcp
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
    def overlaps(self, other):
        return (self.start_seq <= other.start_seq and \
                other.start_seq < self.end_seq) \
                              or \
               (self.start_seq < other.end_seq and \
                other.end_seq <= self.end_seq)

class UDPPacket(object):
    def __init__(self, ts, buf, eth, ip, udp):
        self.ts = ts
        self.buf = buf
        self.eth = eth
        self.ip = ip
        self.udp = udp
    def __repr__(self):
        return `self.udp`

class DNSMessage(object):
    """Holds a dns request or response and some extrated data."""

    def __init__(self, ts, buf, eth, ip, udp, dns, analysis):
        self.ts = ts
        self.buf = buf
        self.eth = eth
        self.ip = ip
        self.udp = udp
        self.dns = dns
        self.analysis = analysis
        self.start = ts
        self.end = ts
        self.duration = 0

        self.map = {}
        self.reverse_map = {}
        self.ips = []
        
        self.is_answer = False
        self.hosts = []

        # Are there questions in the packet?
        if hasattr(self.dns, 'qd'):
            self.hosts = [q.name for q in self.dns.qd]

        #log.critical('HOSTS: %s' % self.hosts)

        # Do we have an answer?
        if hasattr(self.dns, 'an'):
            self.is_answer = True
            answer = self.dns.an
            for rr in answer:
                #log.debug(`answer`)

                # CNAME support (type 5)
                if hasattr(rr, 'type') and rr.type == 5:

                    # Read dns name format
                    def read_labels(rdata):
                        #log.debug('STARTING READ OF: '+`rdata`)
                        ptr = 0
                        labels = []
                        while True:

                            count = unpack('B', rdata[ptr])[0]

                            #log.debug('ptr %d count %d stuff %s' % (
                            #    ptr, count, `rdata[ptr:count]`
                            #))

                            # End of record
                            if count == 0:
                                return '.'.join(labels)

                            # Are we using compression? If so, go back and
                            # figure out where to pull the label from
                            if count & 0xC0:
                                offset = unpack('B',rdata[ptr+1])[0]
                                #log.debug('recuring, offset %d' % (offset))
                                return '.'.join((
                                    '.'.join(labels),
                                    read_labels(self.udp.data[offset:])
                                ))

                            # No compression, the whole name is here
                            else:
                                labels.append(rdata[(ptr+1):(ptr+1+count)])
                            ptr += count + 1

                            #log.debug('  labels: ' + `labels`)

                    data = read_labels(rr.rdata)
                    self.map[rr.name] = data
                    self.reverse_map[data] = rr.name

                # Normal ip address answer
                else:
                    ip = inet_ntoa(rr.rdata)
                    self.ips.append(ip)
                    self.map[rr.name] = ip
                    self.reverse_map[ip] = rr.name

        #log.critical('DNS info for %s' % `self`)
        #log.critical(pformat(self.map))
        #log.critical(pformat(self.reverse_map))
        #log.critical(pformat(self.ips))

    def __repr__(self):
        return `self.dns`

    relative_start = property(
        lambda self: self.start - self.analysis.global_start)
    relative_end = property(
        lambda self: self.end - self.analysis.global_start)
    http_relative_start = property(
        lambda self: self.start - self.analysis.http_start)
    http_relative_end = property(
        lambda self: self.end - self.analysis.http_start)

class DNSQuery(object):
    """Holds all the messages for a single DNS query."""

    def __init__(self, analysis, messages, index = None):
        self.real_dnsquery = self
        self.analysis = analysis
        self.messages = messages
        self.index = index

        # Query Identification
        self.id = messages[0].dns.id if len(messages) else None
        assert all(self.id == msg.dns.id for msg in messages)
        self.host = messages[0].hosts[0] if len(messages) and len(messages[0].hosts) else None
        assert all(
            (self.host == host for host in msg.hosts)
            for msg in messages
        )

        # Time analysis
        self.start = min(msg.ts for msg in self.messages)
        self.end = max(msg.ts for msg in self.messages)
        self.duration = self.end - self.start

    def __repr__(self):
        return '%s <id=%d>' % (self.__class__, self.id)

    relative_start = property(
        lambda self: self.start - self.analysis.global_start)
    relative_end = property(
        lambda self: self.end - self.analysis.global_start)
    http_relative_start = property(
        lambda self: self.start - self.analysis.http_start)
    http_relative_end = property(
        lambda self: self.end - self.analysis.http_start)

    @property
    def durations(self):
        for i, msg in enumerate(self.messages):
            try:
                yield self.messages[i+1].ts - msg.ts
            except IndexError:
                pass

    @classmethod
    def extract(klass, analysis, messages):
        """Returns a list of queries given a list of DNSMessages"""
        from collections import defaultdict
        messages_by_id = defaultdict(list)
        message_ids = []
        for msg in messages:
            if msg.dns.id not in messages_by_id:
                message_ids.append(msg.dns.id)
            messages_by_id[msg.dns.id].append(msg)
        #log.critical('EXTRACT %s' % pformat(dict(messages_by_id)))
        #log.critical('MESSAGE IDS %s' % message_ids)
        return [
            DNSQuery(analysis, messages_by_id[id], count)
            for count, id in enumerate(message_ids)
        ]
        

class DNSManager(object):
    """A class to hold DNS messages, queries, maps and other information."""

    def __init__(self, analysis, udp_packets = []):

        self.analysis = analysis
        self.messages = []
        self.ips = []
        self.map = {}
        self.reverse_map = {}
        self.chains = {}
        self.real_dnsmanager = self
        self.queries_by_host = {}

        # Turn the UDP into DNS if we can
        for pkt in udp_packets:
            try:
                self.messages.append(
                    DNSMessage(
                        pkt.ts,
                        pkt.buf,
                        pkt.eth,
                        pkt.ip,
                        pkt.udp,
                        DNS(pkt.udp.data),
                        self.analysis
                    )
                )
            except:
                log.critical(format_exc())
                log.critical('Looks like %s is not a valid DNS packet?' % pkt)
                raise

        # Extract unique queries
        self.queries = DNSQuery.extract(self.analysis, self.messages)
        #log.critical('======\nQueries %s\n======' % '\n'.join([pformat({'id':q.id, 'host':q.host, 'dns':q.messages}) for q in self.queries]))

        #log.critical('DURATIONS: %s' % [[d for d in q.durations] for q in self.queries])
        #log.critical('HTTP RELATIVE STARTS: %s' % [q.http_relative_start for q in self.queries])

        # Aggregate the DNS map
        for query in self.queries:
            for msg in query.messages:
                self.map.update(msg.map)
                self.reverse_map.update(msg.reverse_map)
                self.ips += msg.ips
                for key in msg.map.keys():
                    self.queries_by_host[key] = query
        
        # Remap dns into chains
        for ip in self.ips:
            next = ip
            chain = []
            while True:
                if next in self.reverse_map:
                    next = self.reverse_map[next]
                    chain.append(next)
                else:
                    break
            self.chains[ip] = chain

        #log.debug(pformat(self.chains))


    def hookup(self):
        """
        Populate objects flows with dns information (if they triggered
        the lookup in the first place).
        
        This should be called after the DNSManager's analysis object
        has populated all of its http objects and flows.
        """

        # Consistency check - all objects in a flow are from same host
        for flow in self.analysis.http_flows:
            first = flow.requests[0]
            for request, response in flow.pairs:
                assert request.headers['host'] == first.headers['host']

        # Assign dns queries - XXX dont' use brute force here
        for query in self.queries:
            for request, response in self.analysis.pairs:
                if request.headers['host'] == query.host:
                    request.dns_query = query
                    request.flow.dns_query = query
                    break

        # Insert DNS information into the object
        #for flow in self.analysis.http_flows:
        #    if flow.dns_query is not None:
        #        flow.flow_states.insert(0, (flow.dns_query.start, flow.dns_query.end, fs_dnsquery))
        #        if flow.has_handshake:
        #            flow.flow_states.insert(1, (flow.dns_query.end, flow.syn.ts, fs_handshake_done))
        #        elif len(flow.pairs) > 0:
        #            flow.flow_states.insert(1, (flow.dns_query.end, flow.pairs[0][0].start, fs_handshake_done))
                
  
class HTTPMessage(object):
    """
    The dpkt.http.Message class is useful, but we need to add our own
    metadata to it, which is where this class comes in. Note that this
    class is abstract and it's subclasses need to inherit from
    dpkt.http.Request/Response.
    """

    def __init__(self, data, start_seq, sequence_list, flow):
        """
        The data parameter is a stream to be tested for an HTTP message. If
        one is sucessfully found, the message is parsed into attributes of
        this object like obj.body and obj.headers. The remaining data in the
        stream is available as obj.data, and can be used to parse the next
        message.

        The start_seq parameter is the sequence number of the first byte in
        data, and sequence_list is used to figure out which packets contained
        data from this HTTP message.
        """
        super(HTTPMessage, self).__init__(data)

        self.analysis = flow.analysis
        self.flow = flow

        self.len = len(data) - len(self.data) # how much data did we consume?
        self.start_seq = start_seq
        self.end_seq = start_seq + self.len - 1

        self.dns_query = None

        # Figure out what packets correspond to our message by adding
        # packets that overlap our sequence numbers in any way
        self.packets = [
            pkt for (start, end), pkt in sequence_list
            if not (end < self.start_seq or start > self.end_seq)
        ]
        #s = sorted(self.packets, key = lambda p:p.ts)
        #assert self.packets == s
        #log.debug('reverse-- %d %s %s %s' %(self.flow.index,self.start_seq,self.__class__.__name__,`self.body`[:30]))

        min_ts = self.packets[0].ts
        max_ts = self.packets[0].ts
        for pkt in self.packets:
            if min_ts > pkt.ts:
                min_ts = pkt.ts
            if max_ts < pkt.ts:
                max_ts = pkt.ts

        self.start = min_ts
        self.end = max_ts
        self.duration = self.end - self.start
        self.header_length = self.len - len(self.body)

        #if self.duration < 0.0:
        #    log.debug('BAD HTTP Message: %d-%d, duration %f, packets %s' % (self.start_seq, self.end_seq, self.duration, [(start, end, pkt.ts) for (start,end),pkt in sequence_list if not (end < self.start_seq or start > self.end_seq)]))

        # Calculate RTT stats
        try:
            self.rtt_list = [
                (pkt.rtt, pkt) for pkt in self.packets 
                if pkt.rtt is not None
            ]
            self.rtt_avg = \
                sum(rtt for rtt, pkt in self.rtt_list) \
                    / float(len(self.rtt_list)) \
                        if len(self.rtt_list) else None
            self.rtt_max = \
                max(rtt for rtt, pkt in self.rtt_list) \
                    if len(self.rtt_list) else None
            self.rtt_min = \
                min(rtt for rtt, pkt in self.rtt_list) \
                    if len(self.rtt_list) else None
            #log.debug("\tOBJECT RTT: avg %.3f max %.3f min %.3f" % (
            #    self.rtt_avg, self.rtt_max, self.rtt_min
            #))
        except:
            log.critical(traceback.format_exc())

        self.index = None
        self.total_bytes = len(self)

    relative_start = property(
        lambda self: self.start - self.analysis.global_start)
    relative_end = property(
        lambda self: self.end - self.analysis.global_start)
    http_relative_start = property(
        lambda self: self.start - self.analysis.http_start)
    http_relative_end = property(
        lambda self: self.end - self.analysis.http_start)
        
    def __repr__(self):
        return '%s <version=%s body=%s start=%s, end=%s>' % (
            self.__class__.__name__,
            self.version,
            `self.body[:21]`,
            self.start,
            self.end,
        )
    def __eq__(self, other):
        return not self.__ne__(other)
    def __ne__(self, other):
        if isinstance(other, HTTPMessage):
            return self.__cmp__(other) != 0
        else:
            return True
    def __cmp__(self, other):
        if self is other:
            return 0
        return cmp(self.sort_start, other.sort_start)
    sort_start = property(lambda self: self.start)

class HTTPRequest(HTTPMessage, Request):

    def __init__(self, *args, **kwargs):
        super(HTTPRequest, self).__init__(*args, **kwargs)
        self.response_ = None
        
    # The start for sorting purposes is the initial syn timestamp in the case
    # that we are the first request and the flow has a handshake
    sort_start = property(
        lambda self: self.flow.start \
            if self.is_first and self.flow.has_handshake \
                else (self.start \
                    if self.dns_query is None \
                        else self.dns_query.start)
    )

    def base_uri_trunc(self):
        import os
        if self.uri == '/':
            return self.uri
        else:
            uri = self.uri.split('?')[0]
            return os.path.basename(uri)[:19]
    base_uri_trunc = property(base_uri_trunc)

    clean_uri = property(
        lambda self: self.uri.split('?')[0])

    @property
    def http_host(self):
        return self.headers.get('host', '')
    
    @property
    def real_request(self):
        return self

    @property
    def flow_host(self):
        return self.flow.host
    
    @property
    def fully_qualified_uri(self):
        return urllib.basejoin('http://%s' % self.http_host, self.uri)
    fully_qualified_url = fully_qualified_uri

    def query_string(self):
        parts = self.uri.split('?')
        if len(parts) > 1:
            return ''.join(parts[1:])
    query_string = property(query_string)

    def time_until_response(self):
        for request, response in self.flow.pairs:
            if request == self:
                #if response.start < self.end:
                    #log.debug('WHOOPS: fl %d start %s len %s end %s uri %s packets %s' %(
                    #    response.flow.index, 
                    #    response.start_seq, 
                    #    response.len, 
                    #    response.end_seq, 
                    #    pformat(request.uri),
                    #    pformat(['ts %s seq %s len %s end %s data %s' % (
                    #        p.ts,
                    #        p.tcp.seq,
                    #        len(p.tcp.data),
                    #        p.tcp.seq + len(p.tcp.data),
                    #        p.tcp.data) for p in response.packets])))
                return response.start - self.end
    time_until_response = property(time_until_response)

    def response(self):
        if self.response_ != None:
            return self.response_
        for request, response in self.flow.pairs:
            if request == self:
                self.response_ = response
                return response
    response = property(response)

    pair_duration = property(
        lambda self: self.response.end - self.start
    )

    sort_duration = property(
        lambda self: self.response.end - self.sort_start
    )

    is_first = property(
        lambda self: self is self.flow.requests[0]
    )

    http_relative_sort_start = property(
        lambda self: self.sort_start - self.analysis.http_start 
    )
    http_relative_start = property(
        lambda self: self.start - self.analysis.http_start
    )

css_re = re(
    r'url\s*(?:'
        r'"([^"]*)"'   r'|'
        r'\('
            r'(?:'
                r'"([^"]*)"'  r'|'
                r'([^\;)]+)'
            r')'
        r'\)'
    r')'
)

import gzip, zlib
import cStringIO

class HTTPResponse(HTTPMessage, Response):

    def __init__(self, *args, **kwargs):
        super(HTTPResponse, self).__init__(*args, **kwargs)

        # Attempt to decompress if necessary
        self.compression = None
        self.body_uncompressed = self.body

        # Handle GZIP
        if self.headers.get('content-encoding', '').lower().find('gzip') != -1:
            #log.debug('FOUND GZIP... DECOMPRESSING %s' % `self.body`)
            self.compression = 'gzip'
            try:
                self.body_uncompressed = gzip.GzipFile(
                    fileobj = cStringIO.StringIO(self.body)
                ).read()
            except:
                self.analysis.errors.append(sys.exc_info())
            #log.debug('GZIP DONE before %d after %d' % (len(self.body_uncompressed), len(self.body)))

        # Handle DEFLATE
        if self.headers.get('content-encoding', '').lower().find('deflate') != -1:
            #log.debug('FOUND DEFLATE... DECOMPRESSING %s' % `self.body`)
            self.compression = 'deflate'
            try:
                # NOTE: wbits = -15 is a undocumented feature in python (it's
                # documented in zlib) that gets rid of the header so we can
                # do raw deflate. See: http://bugs.python.org/issue5784
                self.body_uncompressed = zlib.decompress(self.body, -15)
            except:
                self.analysis.errors.append(sys.exc_info())
            #log.debug('DEFLATE DONE before %d after %d' % (len(self.body_uncompressed), len(self.body)))

        self.compression_ratio = \
            len(max(self.body,1)) / float(max(len(self.body_uncompressed),1))
        self.compression_percent = int((1 - self.compression_ratio) * 100)

        # TODO: Is there a better way to detect an image? PIL?
        self.is_image = False
        if self.content_type.split('/')[0].strip().lower().startswith('image'):
            self.is_image = True

    content_type = property(
        lambda self: self.headers.get('content-type', 'unknown').split(';')[0].strip()
    )

    @property
    def real_response(self):
        return self

    @property
    def html_resources(self):
        """
        Yields a tuple of information about each outside resource found in
        this object. The tuple has the following information:
        (
            pos,    # relative sequence number of this object's tag
            url,    # external url for this object
            content_type,
            script, # boolean - is this object a script?
            defer,  # boolean - does this script have a defer attribute?
            sibling_urls,  # a list of urls of siblings of this script (those
                           # potentially elligible for concatenation)
            sibling_index, # zero-based index of position amongst siblings
        )
        """
        try:
            soup = BeautifulSoup(self.body_uncompressed)
            #soup = TidyBeautifulSoup(self.body_uncompressed)
        except:
            import os
            fd, fname = tempfile.mkstemp('.html')
            os.write(fd, self.body_uncompressed)
            os.write(fd, '\n')
            os.write(fd, '<!-- html headers:\n')
            for header, val in self.headers.iteritems():
                os.write(fd, "%s: %s\n" % (header, val))
            os.write(fd, '-->\n')
            os.close(fd)
            log.warn('%s is not HTML, wrote to %s' % (repr(self._request.fully_qualified_url), fname))
            return

        for tag in soup.findAll([
            'link',
            'img',
            'script',
            'embed',
            'object',
            'iframe'
        ]):
            #print 'found: %s' % tag

            lower_name = tag.name.lower()

            # Find siblings for concatenation on CSS and scripts
            siblings = []
            sibling_index = 0
            if lower_name == 'link' or lower_name == 'script':
                before = tag.findPreviousSiblings(str(lower_name))
                after = tag.findNextSiblings(str(lower_name)) 
                siblings = before + after
                sibling_index = len(before)
                
            # Special case for link tags
            if lower_name == 'link':
                if tag['rel'] == 'stylesheet':
                    sibling_urls = []
                    for s in siblings:
                        try:
                            sibling_urls.append(urllib.basejoin(
                                self._request.fully_qualified_url, s['href']
                            ))
                        except:
                            pass
                    yield (
                        tag.position,
                        urllib.basejoin(self._request.fully_qualified_url, tag['href']),
                        'text/css',
                        False,
                        False,
                        sibling_urls,
                        sibling_index,
                    )

            # General case
            else:
                keylist = zip(*tag.attrs)
                if len(keylist) > 0 and 'src' in keylist[0]:
                    keys = keylist[0]
                    url = urllib.basejoin(self._request.fully_qualified_url, tag['src'])
                    sibling_urls = []
                    for s in siblings:
                        try:
                            sibling_urls.append(urllib.basejoin(
                                    self._request.fully_qualified_url, s['src']
                            ))
                        except:
                            pass
                    yield (
                        tag.position, 
                        url, 
                        'text/javascript',
                        lower_name == 'script', 
                        'defer' in keys,
                        sibling_urls,
                        sibling_index,
                    )

                # Special case for inline scripts (no url reference)           
                elif lower_name == 'script':
                    yield (
                        tag.position,
                        None,
                        'text/javascript',
                        True,
                        False,
                        [],
                        0,
                    )

    @property
    def css_resources(self):
        return list(
            urllib.basejoin(self._request.fully_qualified_url, url)
            for url in chain(*css_re.findall(self.body_uncompressed))
            if url
        )

    def next_pair(self):
        if hasattr(self, '_next_pair'):
            return self._next_pair
        for i, (request, response) in enumerate(self.flow.pairs):
            if response == self and len(self.flow.pairs) > i+1:
                self._next_pair = self.flow.pairs[i+1]
                return self._next_pair
        self._next_pair = None
        return None
    next_pair = property(next_pair)

    def next_request(self):
        if self.next_pair:
            request, response = self.next_pair
            return request
    next_request = property(next_request)

    def next_response(self):
        if self.next_pair:
            request, response = self.next_pair
            return response
    next_response = property(next_response)

    def time_until_next_request(self):
        if self.next_pair:
            next_request, next_response = self.next_pair
            return max(next_request.start - self.end, 0)
        return None
    time_until_next_request = property(time_until_next_request)

class WaterfallAnalysis(object):

    def __init__(self, pcap_file):

        self.pcap_filename = pcap_file.name
        self.errors = []
        self.pairs = []

        self.flowdict = {}

        self.dns = DNSManager(self)
        self.dns_candidates = []

        self.tcp_flows = []
        self.tcp_problem_flows = []

        self.http_flows = []
        self.http_problem_flows = []

        self.global_start = sys.maxint
        self.global_end = 0

        self.snaplen = None
        self.bad_snaplen = False
        self.max_len = 0
        
        self.http_start = None
        self.http_end = None

        self.http_duration = None

        self.start = None
        self.end = None
        self.duration = None

        self.site_name = None

        self.num_https = None
        self.compression = None
        self.uncompressed_len = None
        self.compressed_len = None
        self.compression_ratio = None
        self.compression_percent = None

        self.tcp_upload = None
        self.tcp_download = None

        self.resources = {}

        self.forward_rtt_avg = None
        self.reverse_rtt_avg = None
        
        self.forward_rtt_max = None
        self.reverse_rtt_max = None

        self.forward_rtt_min = None
        self.reverse_rtt_min = None

        self.min_forward_rtt_min = None
        self.min_reverse_rtt_min = None

        self.max_forward_rtt_min = None
        self.max_reverse_rtt_min = None

        self.rtt_avg = None
        self.rtt_max = None
        self.rtt_min = None

        self.forward_rtt_est = None
        self.reverse_rtt_est = None
        self.closer_to_client = None
        
        self.forward_rtt_est = None
        self.reverse_rtt_est = None
        self.closer_to_client = None
        self.total_rtt_est = None

        self.user_agent = None
        self.browser_cap = None
        self.browser_name = None
        self.browser_general = None

        try:

            pcap = ModifiedReader(pcap_file)

            # Loop through captured packets
            for ts, buf, hdr in pcap:
                try:
                    self.max_len = max(self.max_len, hdr.len)
                    if hdr.len > pcap.snaplen:
                        self.bad_snaplen = True

                    eth = Ethernet(buf)

                    # Track relative start and end time
                    self.global_start = min(ts, self.global_start)
                    self.global_end = max(ts, self.global_end)

                    if isinstance(eth.data, IP):
                        ip = eth.data

                        # Grab UDP Packets
                        if isinstance(ip.data, UDP):
                            udp = ip.data
                            if udp.sport == 53 or udp.dport == 53:
                                self.dns_candidates.append(
                                    UDPPacket(ts, buf, eth, ip, udp)
                                )

                        # Grab TCP Packets
                        if isinstance(ip.data, TCP):
                            tcp = ip.data

                            s = (ip.src, tcp.sport)
                            d = (ip.dst, tcp.dport)
                            socket = (d, s) if (d, s) in self.flowdict else (s, d)
                            self.flowdict.setdefault(socket,[]).append(
                                TCPPacket(ts,buf,eth,ip,tcp)
                            )

                except Exception, e:
                    self.errors.append(sys.exc_info())

            # Create our dns manager
            try:
                self.dns = DNSManager(self, self.dns_candidates)
            except Exception, e:
                self.errors.append(sys.exc_info())

            ## Create list of tcp flows
            for i, (socket, packets) in enumerate(self.flowdict.items()):
                try:
                    self.tcp_flows.append(
                        TCPFlow(socket, self, i, packets))
                except Exception, e:
                    #log.debug(format_exc())
                    #log.debug('Looks like %s is not a valid TCP flow?' % flow_str(socket))
                    self.tcp_problem_flows.append((socket, packets))
                    self.errors.append(sys.exc_info())
            self.tcp_flows.sort(key = lambda f:f.start)

            # Renumber based on sort order
            for i in range(len(self.tcp_flows)):
                self.tcp_flows[i].index = i

            # Create list of HTTP flows
            count = 0
            for flow in self.tcp_flows:
                try:
                    self.http_flows.append(
                        HTTPFlow(flow.socket, self, count, flow.packets)
                    )
                    count += 1
                except Exception, e:
                    #log.debug(format_exc())
                    #log.debug('Looks like %s is not a valid HTTP flow?' % flow_str(flow.socket))
                    self.http_problem_flows.append(flow)

            #log.debug('TCP problem flows: %s' % `self.tcp_problem_flows`)
            #log.debug('HTTP problem flows: %s' % `self.http_problem_flows`)

            if not len(self.http_flows):
                raise NoFlowsError('No http flows')

            # Make a sorted list of *all* the reqeust/response pairs
            for flow in self.http_flows:
                self.pairs += flow.pairs
            self.pairs.sort()
            # Put a global index on each request/response
            for i in xrange(len(self.pairs)):
                request, response = self.pairs[i]
                request.index, response.index = i,i
                request.orig_index, response.orig_index = i,i
            #log.debug(`self.pairs`)

            # Hook up DNS to objects and flows
            self.dns.hookup()

            # Start is the first packet we've seen in a HTTP flow
            self.http_start = safe_min(
                f.dns_query.start 
                    if f.dns_query and f.dns_query.start
                        else f.start
                for f in self.http_flows
            )

            if not self.http_start:
                raise Exception('http_start is None! %s' % `[ 
                    f.dns_query.start 
                        if f.dns_query and f.dns_query.start
                            else f.start
                    for f in self.http_flows
                ]`)

            # End is the last packet we've seen in a request or response
            self.http_end = max(
                max(response.end, request.end)
                for request, response in self.pairs
            )

            self.http_duration = self.http_end - self.http_start

            self.start = self.global_start
            self.end = self.global_end
            self.duration = self.end - self.start

            # Try for a site name
            self.site_name = None
            for request, response in self.pairs:                       
                # First attempt to use the host for the first 200 OK
                if response.status == '200':                           
                    self.site_name = request.headers.get('host', None)
                    if self.site_name is not None:
                        break

            # If that doesn't work, then use the first response host
            if not self.site_name and len(self.pairs):
                request, response = self.pairs[0]
                self.site_name = request.headers.get('host', None) 

            # Did we have https involved?
            self.num_https = sum(
                flow.dport == 443 or flow.sport == 443
                for flow in self.tcp_flows
            )

            # Compression stats
            if any(response.compression for request, response in self.pairs):
                self.compression = ' and '.join(set(
                    response.compression for request, response in self.pairs
                    if response.compression
                ))
            else:
                self.compression = None
            self.uncompressed_len = sum(
                len(response.body_uncompressed) 
                for request, response in self.pairs
            )
            self.compressed_len = sum(
                len(response.body) 
                for request, response in self.pairs
            )
            self.compression_ratio = \
                float(self.compressed_len) / float(max(self.uncompressed_len,1))
            self.compression_percent = \
                int((1 - self.compression_ratio) * 100)

            # Total data for http
            self.tcp_upload = safe_sum(f.tcp_upload for f in self.http_flows)
            self.tcp_download = safe_sum(f.tcp_download for f in self.http_flows)

            # create a resource mapping, from URL to request, response pairs
            self.resources = {}
            for request, response in self.pairs:
                self.resources[request.fully_qualified_url] = request, response
                request._response = response
                response._request = request

            # hook up flow.hostname based on http, or dns if it wasn't there.
            for flow in self.tcp_flows:
                flow.hostname_source = 0 # raw ip
                flow.hostname = flow.dip
                if flow.dip in self.dns.chains:
                    dns = self.dns.chains[flow.dip]
                    if flow.hostname is flow.dip:
                        flow.hostname_source = 2
                        flow.hostname = self.dns.chains[flow.dip][-1]
                    #flow.dns_idx = ??
            for flow in self.http_flows:
                flow.hostname_source = 0 # raw ip
                flow.hostname = flow.dip
                if len(flow.pairs) > 0:
                    request, response = flow.pairs[0]
                    flow_host = request.headers.get('host', None)
                    hosts_same = True
                    for request, response in flow.pairs[1:]:
                        host = request.headers.get('host', None)
                        if host != flow_host:
                            hosts_same = False
                            if flow_host is None:
                                flow_host = host
                            break
                    if flow_host is not None:
                        flow.hostname = flow_host
                        if hosts_same:
                            flow.hostname_source = 0
                        else:
                            flow.hostname_source = 1
                if flow.dip in self.dns.chains:
                    dns = self.dns.chains[flow.dip]
                    if flow.hostname is flow.dip:
                        flow.hostname_source = 2
                        flow.hostname = self.dns.chains[flow.dip][-1]
                    #flow.dns_idx = ??

            # Calculate average RTT stats

            # AVG
            self.forward_rtt_avg = safe_average(
                self.http_flows, lambda flow: flow.forward_rtt_avg)
            self.reverse_rtt_avg = safe_average(
                self.http_flows, lambda flow: flow.reverse_rtt_avg)
            
            # MAX
            self.forward_rtt_max = safe_average(
                self.http_flows, lambda flow: flow.forward_rtt_max)
            self.reverse_rtt_max = safe_average(
                self.http_flows, lambda flow: flow.reverse_rtt_max)

            # MIN
            self.forward_rtt_min = safe_average(
                self.http_flows, lambda flow: flow.forward_rtt_min)
            self.reverse_rtt_min = safe_average(
                self.http_flows, lambda flow: flow.reverse_rtt_min)

            # MIN of the MIN
            self.min_forward_rtt_min = safe_min(
                self.http_flows, lambda flow: flow.forward_rtt_min)
            self.min_reverse_rtt_min = safe_min(
                self.http_flows, lambda flow: flow.reverse_rtt_min)
            # MAX of the MIN
            self.max_forward_rtt_min = safe_max(
                self.http_flows, lambda flow: flow.forward_rtt_min)
            self.max_reverse_rtt_min = safe_max(
                self.http_flows, lambda flow: flow.reverse_rtt_min)

            #log.debug("\tFORWARD RTT: avg %-10f max %-10f min %-10f" % (
            #    self.forward_rtt_avg, self.forward_rtt_max, self.forward_rtt_min
            #))
            #log.debug("\tREVERSE RTT: avg %-10f max %-10f min %-10f" % (
            #    self.reverse_rtt_avg, self.reverse_rtt_max, self.reverse_rtt_min
            #))

            # Average of each value
            self.rtt_avg = safe_average(
                self.http_flows, lambda flow: flow.rtt_avg)
            self.rtt_max = safe_average(
                self.http_flows, lambda flow: flow.rtt_max)
            self.rtt_min = safe_average(
                self.http_flows, lambda flow: flow.rtt_min)

            #log.debug("\tTOTAL RTT: avg %-10f max %-10f min %-10f" % (
            #    self.rtt_avg, self.rtt_max, self.rtt_min
            #))

            # Estimate capture/client distance
            if self.forward_rtt_min > self.reverse_rtt_min:
                self.forward_rtt_est = self.max_forward_rtt_min
                self.reverse_rtt_est = self.min_reverse_rtt_min
                self.closer_to_client = True
            else:
                self.forward_rtt_est = self.min_forward_rtt_min
                self.reverse_rtt_est = self.max_reverse_rtt_min
                self.closer_to_client = False
            self.total_rtt_est = self.forward_rtt_est + self.reverse_rtt_est

            # Most prominent browser
            user_agents = {}
            for http_flow in self.http_flows:
                for request, response in http_flow.pairs:
                    agent = request.headers.get('user-agent')
                    if agent in user_agents:
                        user_agents[agent] += 1
                    else:
                        user_agents[agent] = 0
            self.user_agent = user_agents.keys()[0] or None
            if self.user_agent:
                self.browser_cap = bc(self.user_agent)
                if self.browser_cap:
                    self.browser_name = '%s %s' % (self.browser_cap.name(), '.'.join(self.browser_cap.version()))
                    self.browser_general = '%s %s' % (self.browser_cap.name(), self.browser_cap.version()[0])
                else:
                    self.browser_name = self.browser_general = None
            else:
                self.browser_cap = self.browser_name = self.browser_general = None

            # delete 
            # Response size histogram
            #~ try:
                #~ from pygooglechart import SimpleLineChart, Axis
                #~ from histogram import Histogram
                #~ from math import log as logarithm
                #~ h = Histogram(14, lambda x:logarithm(max(1,x/1024.0),2))
                #~ h += (
                    #~ len(response.body)
                    #~ for r, response in self.pairs
                #~ )
                #~ chart = SimpleLineChart(300,100)
                #~ chart.add_data(h)
                #~ chart.set_axis_labels(Axis.LEFT, range(
                        #~ 0,      # start is 0
                        #~ max(h), # end is the highest number seen
                        #~ max(1,max(h)/5) # step is height/5 or else 1
                    #~ )
                #~ )
                #~ chart.set_axis_labels(Axis.BOTTOM, ['','4k','','16k','','64k','','256k','','1M','','4M', '', '16M+'])
                #~ self.size_chart_url = chart.get_url()
            #~ except Exception, e:
                #~ self.errors.append(sys.exc_info())

            #delete
            # Mime type chart
            #~ try:
                #~ from pygooglechart import PieChart3D
                #~ try:
                    #~ from django.template.defaultfilters import filesizeformat
                    #~ filesizeformat(1)
                #~ except ImportError:
                    #~ def filesizeformat(v):
                        #~ return str(v)
                #~ mime_types = {}
                #~ for request, response in self.pairs:
                    #~ type = response.headers.get(
                        #~ 'content-type', '').split(';')[0].strip()
                    #~ mime_types.setdefault(type, 0)
                    #~ mime_types[type] += len(response.body)
                #~ # Sort by total size
                #~ if '' in mime_types:
                    #~ del mime_types['']
                #~ items = sorted(mime_types.items(), 
                    #~ key = lambda x:x[1], reverse=True)
                #~ #log.debug('ITEMS:' + pformat(items))
                #~ top = items[:5]  # take the top 5 items
                #~ rest = items[5:]
                #~ new = dict(top)
                #~ new['/other'] = sum(dict(rest).values())
                #~ #log.debug('NEW:' + pformat(sorted(new.items(), key = lambda x:x[1])))
                #~ chart = PieChart3D(500,100)
                #~ chart.add_data(sorted([new[t] for t in new]))
                #~ chart.set_pie_labels(
                    #~ '%s (%s)' % (k.split('/')[1], filesizeformat(v))
                    #~ for k, v in sorted(new.items(), key = lambda x:x[1])
                #~ )
                #~ chart.set_colours([ '008000', '00aaaa', '3765D9', '9E42EE', '9EDE7C', 'EC7612', 'aaaa00', 'cc0000', ])
                #~ self.mime_chart_url = chart.get_url()
            #~ except Exception, e:
                #~ self.errors.append(sys.exc_info())

        except NoFlowsError, e:
            pass
        except Exception, e:
            self.errors.append(sys.exc_info())


def main(argv):
    import os
    import traceback

    if len(argv) != 2 and len(argv) != 3:
        print "Usage: %s <pcap_file>, or %s test [<pcap directory>(default /var/pcap)]" % (argv[0], argv[0])
        exit(-1)

    fname = argv[1]
    if fname == 'test':
        if len(argv) > 2:
            dirname = argv[2]
        else:
            dirname = '/var/pcap'

        def analyze_pcap(filename):
            if filename.endswith('.pcap'):
                print 'TESTING %s' % filename
                an = WaterfallAnalysis(file(filename))

                # Print all errors indented
                for error in an.errors:
                    print '\t' + '\n\t'.join(
                        ''.join(
                            traceback.format_exception(*error)
                        ).split('\n')
                    )

                #log.critical(['%s' % flow.flow_states for flow in an.http_flows])
                #log.critical(['%s' % flow.flow_colors for flow in an.http_flows])
                #log.critical(['%s' % flow.flow_durations for flow in an.http_flows])

                # Excersize all attributes
                for attr in dir(an):
                    try:
                        getattr(an, attr)
                    except:
                        print '\tError excersizing %s attribute' % attr
                        print '\t' + '\n\t'.join(
                            ''.join(
                                traceback.format_exception(sys.exc_info())
                            ).split('\n')
                        )

                for request, response in an.pairs:
                    stuff = [x for x in response.html_resources if len(x[5])]
                    print stuff
                    for pos, url, ctyp, script, defer, sib_urls, sib_index in stuff:
                        print
                        sib_urls.insert(sib_index, url)
                        for i, sib in enumerate(sib_urls):
                            if sib == url:
                                print '*',
                            print '%s' % sib
            else:
                print 'SKIPPING %s' % filename
            

        # Go through all available pcaps and test for errors
        if os.path.isdir(dirname):
            for dirpath, dirnames, filenames in os.walk(dirname):
                for filename in filenames:
                    fullpath = os.path.join(dirpath, filename)
                    analyze_pcap(fullpath)
        elif os.path.isfile(dirname):
            analyze_pcap(dirname)
        else:
            log.critical('Don\'t know how to open %s' % dirname)
            
    else:
        an = WaterfallAnalysis(file(fname))
        for (ex, msg, trace) in an.errors:
            traceback.print_exception(type(ex), ex, trace)

        for flow in an.http_flows:
            if len(flow.pairs) > 1:
                assert flow.pairs[0][0].is_first
                assert not flow.pairs[1][0].is_first

        wrote = set()
        for request, response in an.pairs:
            basename = os.path.basename(request.clean_uri)
            basefname = os.path.basename(fname)
            basename = basename.split(';', 1)[0]
            if basename == '' or basename == '/':
                basename = 'base'
            basename = basename.replace(':','_')

            dirname = os.path.join('objs', basefname)
            if not os.path.exists(dirname):
                os.makedirs(dirname)

            outname = os.path.join(dirname, basename)
            outmeta = outname+'.meta'
            i = 0
            while os.path.exists(outname) or os.path.exists(outmeta):
                outname = os.path.join(dirname, '%d.%s' % (i, basename))
                outmeta = outname+'.meta'
                i += 1
            f = open(outname, 'w')
            f.write(response.body_uncompressed)
            f.close()
            metaf = open(outmeta, 'w')
            print >>metaf, 'Request: %d headers, %d bytes of body' % (len(request.headers), len(request.body))
            print >>metaf, '%s %s %s' % (request.method, request.uri, request.version)
            for h in request.headers:
                print >>metaf, '%s: %s' % (h, request.headers[h])
            if len(request.body) > 0:
                metaf.write(request.body)
            print >>metaf
            print >>metaf, '------------ Response (%d hdrs, %d bytes of body) --------------' % (len(response.headers), len(response.body))
            print >>metaf, '%s %s' % (response.status, response.version)
            for h in response.headers:
                print >>metaf, '%s: %s' % (h, response.headers[h])

            metaf.close()

        for request, response in an.pairs:
            #print `response.next_pair`
            #print `response.next_request`
            #print `response.next_response`
            #print `response.time_until_next_request`
            #print `response.flow.http_duration`
            if request.is_first:
                if request.http_relative_sort_start != request.flow.http_relative_start:
                    print `request.http_relative_sort_start`
                    print `request.flow.http_relative_start`


    raise SystemExit(0)

if __name__ == '__main__':
    import sys
    main(sys.argv)

