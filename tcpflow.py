HANDSHAKE_DETECTION_TRY_LIMIT = 10 # how many packets to go through looking for a handshake

import tcpseq as seq # hopefully no name collisions
from sortedcollection import SortedCollection
from dpkt.tcp import *

class TCPFlow:
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
        self.fwd = TCPDirection(self)
        self.rev = TCPDirection(self)
        self.handshake = None # don't bother for now
        self.socket = None
        self.packets = []
    def add(self, pkt):
        '''
        called for every packet coming in, instead of iterating through
        a list
        '''
        # make sure packet is in time order
        if len(self.packets): # if we have received packets before...
            if self.packets[-1].ts > pkt.ts: # if this one is out of order...
                # error out
                raise ValueError("packet added to TCPFlow out of chronological order")
        self.packets.append(pkt)
        # look out for handshake
        # add it to the appropriate direction, if we've found or given up on finding handshake
        if self.handshake is not None:
            self.merge_pkt(pkt)
        else: # if handshake is None, we're still looking for a handshake
            if len(self.packets) > 13: # or something like that
                # give up
                self.handshake = False
                self.socket = self.packets[0].socket
                self.flush_packets() # merge all stored packets
            # check last three packets
            elif detect_handshake(self.packets[-3:]): # function handles packets < 3 case
                self.handshake = tuple(self.packets[-3:])
                self.socket = self.handshake[0].socket
                self.flush_packets()
    def flush_packets(self):
        '''
        Flush packet buffer by merging the packets into either fwd or rev.
        '''
        for p in self.packets:
            self.merge_pkt(p)
            
    def merge_pkt(self, pkt):
        '''
        Merges the packet into either the forward or reverse stream.
        '''
        if self.samedir(pkt):
            self.fwd.add(pkt)
        else:
            self.rev.add(pkt)
    def finish(self):
        '''
        Notifies the flow that there are no more packets.
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
        first packet.
        Assumes self.handshake is not None
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
    def writeout_data(self, basename):
        '''
        writes out the data in the flows to two files named basename-fwd.dat and
        basename-rev.dat.
        '''
        with open(basename + '-fwd.dat', 'wb') as f:
            f.write(self.fwd.data)
        with open(basename + '-rev.dat', 'wb') as f:
            f.write(self.rev.data)

class TCPDirection:
    def __init__(self, flow):
        self.arrival_data = [] #[(seq_num, pkt)] # records when a given seq number first arrived
        self.final_arrival_data = None # or [(seq_num, dpkt_time)]
        self.closed_cleanly = False # until proven true
        self.chunks = [] # [TCPChunk] sorted by seq_start
        self.flow = flow # the parent TCPFlow. we need info from it
        self.merging = False
    def add(self, pkt):
        '''
        merge in the packet
        '''
        # discard packets with no payload. we don't care about them here
        if pkt.data == '':
            return
        # attempt to merge packet with existing chunks
        merged = False
        for i in range(len(self.chunks)):
            chunk = self.chunks[i]
            overlapped, result = chunk.merge(pkt, self.create_merge_callback(pkt))
            if overlapped: # if the data overlapped
                # if data was added on the back and there is a chunk after this
                if result[1] and i < (len(self.chunks)-1):
                    # try to merge with the next chunk as well
                    # in case that packet bridged the gap
                    overlapped2, result2 = chunk.merge(self.chunks[i+1])
                    if overlapped2: # if that merge worked
                        assert( (not result2[0]) and (result2[1])) # data should only be added to back
                        del self.chunks[i+1] # remove the now-redundant chunk
                merged = True
                break # skip further chunks
        if not merged:
            # nothing overlapped with the packet
            # we need a new chunk
            self.new_chunk(pkt)
            
    def finish(self):
        '''
        notifies the direction that there are no more packets coming.
        '''
        if self.chunks:
            self.data = self.chunks[0].data
        else:
            self.data = ''
        self.arrival_data = SortedCollection(self.arrival_data, key=lambda v: v[0])
    def calculate_final_arrivals(self):
        '''
        make self.final_arrival_data a SortedCollection. Final arrival
        for a sequence number is when that sequence number of data and all the
        data before it have arrived, that is, when the data is usable by the
        application.
        '''
        self.final_arrival_data = []
        peak_time = 0.0
        for vertex in self.arrival_data: # final arrival vertex always coincides with arrival vertex
            if vertex[1].ts > peak_time:
                peak_time = vertex[1].ts
                self.final_arrival_data.append((vertex[0], vertex[1].ts))
        self.final_arrival_data = SortedCollection(self.final_arrival_data, key=lambda v: v[0])

    def new_chunk(self, pkt):
        '''
        creates a new TCPChunk for the pkt to live in. Only called if an attempt
        has been made to merge the packet with all existing chunks
        '''
        chunk = TCPChunk()
        chunk.merge(pkt, self.create_merge_callback(pkt))
        self.chunks.append(chunk)
        self.sort_chunks() # it would be better to insert the packet sorted
    def sort_chunks(self):
        self.chunks.sort(key=lambda chunk: chunk.seq_start)
    def create_merge_callback(self, pkt):
        '''
        Returns a function that will serve as a callback for TCPChunk. It will
        add the passed sequence number and the packet to self.arrival_data.
        '''
        def callback(seq_num):
            self.arrival_data.append((seq_num, pkt))
        return callback
    def byte_to_seq(self, byte):
        '''
        Converts the passed byte index to a sequence number in the stream. byte
        is assumed to be zero-based.
        '''
        if self.handshake:
            return byte + self.flow.handshake[0].seq + 1
        else:
            return byte + self.flow.first_packet.seq
    
    def seq_arrival(self, seq_num):
        '''
        returns the packet in which the specified sequence number first arrived.
        self.arrival_data must be a SortedCollection at this point; self.finish()
        must have been called.
        '''
        if self.arrival_data:
            return self.arrival_data.find_le(seq_num)
    def seq_final_arrival(self, seq_num):
        '''
        Returns the time at which the seq number had fully arrived.
        self.final_arrival_data must be a SortedCollection; self.finish() must
        have been called.
        '''
        if self.final_arrival_data:
            return self.final_arrival_data.find_le(seq_num)        

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

    def merge(self, new, new_seq_callback = None):
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
        if new.data: # if we have actual data yet (maybe false if there was no init packet)
            # assume self.seq_* are also valid
            if self.data:
                return self.inner_merge((new.seq_start, new.seq_end), new.data, new_seq_callback)
            else:
                # if they have data and we don't, just steal theirs
                self.data = new.data
                self.seq_start = new.seq_start
                self.seq_end = new.seq_end
                if new_seq_callback:
                    new_seq_callback(new.seq_start)
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
        if seq.lt(newseq[0], self.seq_start) and seq.lte(self.seq_start, newseq[1]):
            new_data_length = seq.subtract(self.seq[0], newseq[0])
            self.data = newdata[:new_data_length] + self.data # slice out new data, stick it on the front
            self.seq_start = newseq[0]
            # notifications
            overlapped = True
            added_front_data = True
            if callback:
                callback(newseq[0])
        # back data?
        if seq.lte(newseq[0], self.seq_end) and seq.lt(self.seq_end, newseq[1]):
            new_data_length = seq.subtract(newseq[1], self.seq_end)
            self.data += newdata[-new_data_length:]
            self.seq_end += new_data_length
            # notifications
            overlapped = True
            added_back_data = True
            if callback:
                back_seq_start = newseq[1] - new_data_length # the first seq number of new data in the back
                callback(back_seq_start)
        # completely inside?
        if seq.lte(self.seq_start, newseq[0]) and seq.lte(newseq[1], self.seq_end):
            overlapped = True
        # done
        return (overlapped, (added_front_data, added_back_data))

def detect_handshake(packets):
    '''
    Checks whether the passed list of TCPPacket's represents a valid TCP
    handshake. Returns True or False.
    '''
    if len(packets) < 3:
        return False
    if len(packets) > 3:
        log.error('too many packets for detect_handshake')
        return False
    syn, synack, ack = packets
    fwd_seq = None
    rev_seq = None
    if syn.tcp.flags & TH_SYN and not syn.tcp.flags & TH_ACK:
        # have syn
        fwd_seq = syn.seq # start_seq is the seq field of the segment
        if synack.flags & TH_SYN and synack.flags & TH_ACK and synack.ack == fwd_seq + 1:
            # have synack
            rev_seq = synack.seq
            if ack.flags & TH_ACK and ack.ack == rev_seq + 1 and ack.seq == fwd_seq + 1:
                # have ack
                return True
    return False