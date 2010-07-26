
class TCPFlow(Flow):

    def __repr__(self):
        return '%s <%s, start=%s, rtt=%s>' % (
            self.__class__.__name__,
            flow_str(self.socket),
            self.start,
            str(self.rtt_min)
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
                    segments.append(pkt.tcp.data)
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

