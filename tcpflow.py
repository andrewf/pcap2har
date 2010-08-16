HANDSHAKE_DETECTION_TRY_LIMIT = 10 # how many packets to go through looking for a handshake

import tcpseq as seq # hopefully no name collisions

class TCPFLow:
    '''
    Represents TCP traffic across a given socket, ideally between a TCP
    handshake and clean connection termination.

    Members:
    * fwd, rev = TCPDirection, both sides of the communication stream
    * socket = ((srcip, sport), (dstip, dport)). Used for checking the direction
    of packets. Taken from SYN or first packet.
    * packets = list of TCPPacket's, all packets in the flow
    * first_packet
    * handshake = None or (syn, synack, ack) or False. None while a handshake is
    still being searched for, False when we've given up on finding it.
    '''
    def __init__(self):
        self.fwd = TCPDirection()
        self.rev = TCPDirection()
        last_pkt = None # maybe just use packets[-1]
        self.first_packet = None
        # socket is also used to tell if flow is in merging mode
        self.handshake = None
        packets = []
        handshake_search_pos = 0 # move forward for every packet added where we haven't found the handshake
    def add(self, pkt):
        '''
        called for every packet coming in, instead of iterating through
        a list
        '''
        # make sure packet is in time order
        if last_packet:
            if not self.last_pkt.ts < pkt.ts:
                # error out
                raise ValueError or something
        else:
            first_packet = pkt
        last_pkt = pkt
        packets.append(pkt)
        # look out for handshake
        # add it to the appropriate direction, if we've found or given up on finding handshake
        if self.handshake is not None:
            if self.samedir(pkt):
                self.fwd.add(pkt)
            else:
                self.rev.add(pkt)
        else: # if handshake is None, we're still looking for a handshake
            handshake_candidate = self.packets[self.handshake_search_pos:self.handshake_search_pos+3]
            if detect_handshake(handshake_candidate):
                self.handshake = tuple(handshake_candidate)
                self.socket = handshake[0].socket # use the socket from SYN

    def samedir(self, pkt):
        '''
        returns whether the passed packet is in the same direction as the
        assumed direction of the flow, which is either that of the SYN or the
        first packet.
        '''
        if not self.socket:
            raise RuntimeError("called TCPFlow.samedir before direction is determined")
        src, dst = pkt.socket
        if self.socket == (src, dst):
            return True
        elif self.socket == (dst, src):
            return False
        else:
            raise ValueError("TCPFlow.samedir found a packet from the wrong flow")

class TCPDirection:
    def __init__(self):
        arrival_data = [(seq_num, pkt)] # records when a given seq number first arrived
        final_arrival_data = None or [(seq_num, dpkt_time)]
        closed_cleanly = False # until proven true
    def add(self, pkt):
        '''
        merge in the packet
        '''
        # log new data in arrival_data
    def calculate_final_arrivals(self):
        '''
        make self.final_arrival_data valid, or [(seq_num, time)]
        '''
        self.final_arrival_data = []
    def new_chunk(self, pkt):
        '''
        creates a new TCPChunk for the pkt to live in. Only called if an attempt
        has been made to merge the packet with all existing chunks
        '''
        pass

class TCPChunk:
    '''
    A chunk of data from a TCP stream in the process of being merged. Takes the
    place of the data tuples, ((begin, end), data, logger) in the old algorithm.
    Adds member functions that encapsulate the main merging logic.
    '''
    def __init__(self):
        '''
        Basic initialization on the chunk.
        '''
        self.data = ''
        self.seq_start = None
        self.seq_end = None

    def merge_pkt(self, new, new_seq_callback = None):
        '''
        Attempts to merge the packet or chunk with the existing data. Returns
        details of the operation's success or failure.

        Args:
        pkt = TCPPacket or TCPChunk
        new_seq_callback = callable(int) or None

        new_seq_callback is a function that will be called with sequence numbers
        of the start of data that has arrived for the first time.

        Returns:
        (overlapped, (added_front_data, added_back_data)): (bool, (bool, bool))

        Overlapped indicates whether the packet/chunk overlapped with the
        existing data. If so, you can stop trying to merge with other packets/
        chunks. The bools in the other tuple indicate whether data was added to
        the front or back of the existing data.

        Note that (True, (False, False)) is a valid value, which indicates that
        the new data was completely inside the existing data
        '''
        if self.data: # if we have actual data yet (maybe false if there was no init packet)
            # assume self.seq_* are also valid
            return self.inner_merge((new.seq_start, new.seq_end), pkt.data, new_seq_callback)
        else:
            if new.data: # make sure the packet has payload before eating it
                self.data = new.data
                self.seq_start = new.seq_start
                self.seq_end = new.seq_end
                return (True, (True, True))
            # else, there is no data anywhere
            return (False, (False, False))

    def inner_merge(self, newseq, newdata, callback):
        '''
        Internal implementation function for merging, very similar in interface
        to merge_pkt, but more general. It is used for merging in both packets
        and other TCPChunk's

        Args:
        newseq = (seq_begin, seq_end)
        newdata = string, new data
        callback = see new_seq_callback in merge_pkt

        Returns:
        see merge_pkt
        '''
        # setup
        overlapped = False
        added_front_data = False
        added_back_data = False
        # front data?
        if lt(newseq[0], self.seq_start) and lte(self.seq_start, newseq[1]):
            new_data_length = subtract(self.seq[0], newseq[0])
            self.data = newdata[:new_data_length] + self.data # slice out new data, stick it on the front
            self.seq_start = newseq[0]
            # notifications
            overlapped = True
            added_front_data = True
            if callback: callback(newseq[0])
        # back data?
        if lte(newseq[0], self.seq_end) and lt(self.seq_end, newseq[1]):
            new_data_length = subtract(newseq[1], self.seq_start)
            self.data += newdata[-new_data_length:0]
            self.seq_end += new_data_length
            # notifications
            overlapped = True
            added_back_data = True
            if callback:
                back_seq_start = newseq[1] - (new_data_length - 1) # the first seq number of new data in the back
                callback(back_seq_start)
        # completely inside?
        if lte(self.seq_start, newseq[0]) and lte(newseq[1], self.seq_end):
            overlapped = True
        # done
        return (overlapped, (added_front_data, added_back_data))