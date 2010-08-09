from tcppacket import TCPPacket
from pcaputil import *
from tcpseq import lt, lte, gt, gte
import tcpseq
import logging as log
from dpkt.tcp import * # get all the flag constances

class TCPFlowError(Exception):
    pass

class TCPFlow:
    '''assembles a series of tcp packets into streams of the actual data
    sent.

    Includes forward data (sent) and reverse data (received), from the
    perspective of the SYN-sender.'''
    def __init__(self, packets):
        '''assembles the series. packets is a list of TCPPacket's from the same
        socket. They should be in order of transmission, otherwise there will
        probably be bugs.'''
        self.packets = packets
        #reference point for determining flow direction
        self.socket = self.packets[0].socket
        # discover direction, etc.
        # grab handshake, if possible
        if not self.detect_handshake(packets[:3]):
            log.warning('TCP socket %s appears not to have a handshake' % friendly_socket(self.socket))
        # sort packets 
        self.forward_packets = [pkt for pkt in self.packets if self.samedir(pkt)]
        self.reverse_packets = [pkt for pkt in self.packets if not self.samedir(pkt)]
        # assemble data
        self.forward_data, self.forward_logger = self.assemble_stream(self.forward_packets)
        self.reverse_data, self.reverse_logger = self.assemble_stream(self.reverse_packets)
        # calculate statistics?
        self.start_time = packets[0].ts

    def assemble_stream(self, packets):
        '''does the actual stitching of the passed packets into data.
        packets = [TCPPacket]
        
        returns the stitched data'''
        # store tuples of format: ((seq_begin, seq_end), data_str, arrival_logger)
        # when a new packet's data overlaps with one, pull that out, merge
        # them, and replace it.
        def merge_packet(old, new):
            '''
            merges the data tuple and packet together, if they overlap, and
            returns the new data tuple
            
            old = data tuple ((seq_begin, seq_end), data_str, arrival_logger)
            new = TCPPacket
            '''
            # get stuff out
            arrival_logger = old[2]
            # create the logging callback
            def new_seq_number_callback(seq_num):
                arrival_logger.add(seq_num, new)
            # do it, passing the callback so new data gets logged
            merged = inner_merge(old, ((new.start_seq, new.end_seq), new.data), new_seq_number_callback)
            if merged:
                #return merged data with the arrival_logger tacked back on
                return merged + (arrival_logger,)
            else:
                return None
        
        def inner_merge(old, new, new_seq_number_callback = None):
            '''
            Merges just the two data tuples, with an optional callback to be
            called for new sequence numbers, so they can be logged or whatever.
            
            old = ((begin_seq, end_seq), data)
            new = ((begin_seq, end_seq), data)
            new_seq_number_callback = function(long) or None
            
            Extra data in the tuples is acceptable, but will not be returned
            
            Returns the merged tuple, or None they didn't collide
            '''
            # get data in a mutable, easier-to-work-with form
            oldseq = old[0]
            newseq = new[0]
            finaldata = old[1]
            final_seq_start = oldseq[0]
            final_seq_end =   oldseq[1]
            assert(oldseq[0] <= oldseq[1])
            assert(newseq[0] <= newseq[1])
            # misc state
            collided = False # flag for whether the data overlapped
            # do the merge
            if lt(newseq[0], oldseq[0]) and lte(oldseq[0], newseq[1]):
                # add on front data
                new_data_length = tcpseq.subtract(oldseq[0], newseq[0])
                finaldata = new[1][:new_data_length] + finaldata # slice out just new data, tack it on front
                final_seq_start = newseq[0]
                if new_seq_number_callback: new_seq_number_callback(newseq[0]) # log the new data
                collided = True
            # if there's new data hanging off the back edge...
            if lte(newseq[0], oldseq[1]) and lt(oldseq[1], newseq[1]):
                #add on back data
                new_data_length = tcpseq.subtract(newseq[1], oldseq[1])
                back_seq_start = newseq[1] - (new_data_length - 1) # the first sequence number of the new data on the back end
                finaldata += new[1][-new_data_length:] # slice out the back of the new data
                final_seq_end += new_data_length
                if new_seq_number_callback: new_seq_number_callback(back_seq_start) # log the new data
                collided = True
            # if the new data is completely inside the old data
            if lte(oldseq[0], newseq[0]) and lte(newseq[1], oldseq[1]):
                collided = True # this will just cause the existing data to be returned
            # return new data, or None
            if collided:
                return ((final_seq_start, final_seq_end), finaldata)
            else:
                return None
        # log stuff
        # real start of assemble_stream
        stream_segments = [] # the list of data tuples, pieces of the TCP stream. Sorry for the name collision.
        for pkt in packets:
            if not len(pkt.data): continue # skip packets with no payload
            all_new = True # whether pkt is all new data (needs a new segment, assumed true until proven false)
            for i, olddata in enumerate(stream_segments):
                merged = merge_packet(olddata, pkt)
                if merged:
                    stream_segments[i] = merged # replace old segment with merged one
                    all_new = False
                    break
            # now we've looked through all the existing data
            if all_new: # if we need to make a new packet
                # make a new data segment
                newlogger = TCPDataArrivalLogger()
                newlogger.add(pkt.start_seq, pkt)
                d = ((pkt.start_seq, pkt.end_seq), pkt.data, newlogger)
                stream_segments.append( d )
        # now all packets are accounted for
        # now, segments must be merged
        num_segments = len(stream_segments)
        if not num_segments:
            log.info('TCPFlow.assemble_stream: no data segments')
            return '', TCPDataArrivalLogger()
        elif num_segments == 1:
            # log.debug('TCPFlow.assemble_stream: returning first of', num_segments, 'data chunks')
            return stream_segments[0][1], stream_segments[0][2]
        else: # num_segments > 1
            #merge as many segments as possible with the first one
            iterator = iter(stream_segments)
            final = iterator.next()
            num_merges = 0
            try:
                while True:
                    next = iterator.next()
                    #try to merge
                    merged = inner_merge(final, next)
                    if merged: # merged = ((begin, end), data, logger)
                        num_merges += 1
                        final[2].merge(next[2]) # merge the loggers
                        final = (merged) + (final[2],) # tack on merged logger and store it
            except StopIteration:
                pass
            # log and return
            log.info('TCPFlow.assemble_stream: merged %d chunks out of %d chunks' % (num_merges, num_segments))
            return final[1:] # strip out the sequence numbers
    
    def samedir(self, pkt):
        '''returns whether the packet is in the same direction as the canonic
        direction of the flow.'''
        src, dst = self.socket
        if pkt.socket == (src,dst):
            return True
        elif pkt.socket == (dst, src):
            return False
        else:
            raise TCPFlowError('In TCPFlow.samedir, found a packet that is from the wrong socket')
    def __repr__(self):
        return 'TCPFlow(%s, fwd=%s, rev=%s)' % (
            friendly_socket(self.socket),
            friendly_data(self.forward_data)[:60],
            friendly_data(self.reverse_data)[:60]
        )
    
    def writeout_data(self, basename):
        '''writes out the forward and reverse data of the flow into files named
        basename-fwd.dat and basename-rev.dat, for debugging purposes'''
        with open(basename + '-fwd.dat', 'wb') as f:
            f.write(self.forward_data)
        with open(basename + '-rev.dat', 'wb') as f:
            f.write(self.reverse_data)
    
    def detect_handshake(self, packets):
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
                        
            
class TCPDataArrivalLogger:
    '''
    Keeps track of when TCP data first arrives. does this by storing a
    list/set/whatever of tuples (sequence_number, packet), where sequence_number
    is the first sequence number of the *new* data in packet.
    
    This information, along with the beginning and end sequence numbers of the
    data, allows you to find the packet in which a given sequence number of
    data first arrived, by finding the first number less than the given
    sequence number and then grabbing the associated packet.
    
    This class must be created on a per-buffer basis, and merged whenever the
    buffers are merged.
    '''
    def __init__(self):
        '''
        Initializes the requisite internal data structure.
        '''
        self.list = []
    def add(self, sequence_number, pkt):
        '''
        Adds a sequence-number/packet pair to the data.
        '''
        pass
    def find_packet(self, sequence_number):
        '''
        Returns the packet associated with the first sequence number less than
        or equal to the passed one.
        '''
        raise NotImplementedError('finding packets by sequence number is not yet fully supported')
    def merge(self, other):
        '''
        Merges other's data with this one.
        '''
        pass
