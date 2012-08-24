from operator import itemgetter, attrgetter
import logging

from ..sortedcollection import SortedCollection

import packet
import chunk as tcp
from .. import settings


class Direction(object):
    '''
    Represents data moving in one direction in a TCP flow.

    This class is considered to define an abstract interface for a stream
    of data, used by higher-level protocols. The important parts of this
    interface are these member vars and methods:
    * data: string
    * byte_final_arrival(byte): dpkt timestamp when that byte and all data
        before it had arrived.
    * clear_data(): get rid of all data.

    Members:
    * finished = bool. Indicates whether more packets should be expected.
    * chunks = [tcp.Chunk] or None, sorted by seq_start. None iff data
      has been cleared.
    * flow = tcp.Flow, the flow to which the direction belongs
    * arrival_data = SortedCollection([(seq_num, pkt)])
    * final_arrival_data = SortedCollection([(seq_num, ts)])
    * final_data_chunk = Chunk or None, the chunk that contains the final data,
      only after seq_start is valid and before clear_data
    * final_arrival_pointer = the end sequence number of data that has
      completely arrived
    '''

    def __init__(self, flow):
        '''
        Sets things up for adding packets.

        Args:
        flow = tcp.Flow
        '''
        self.finished = False
        self.flow = flow
        self.arrival_data = SortedCollection(key=itemgetter(0))
        self.final_arrival_data = SortedCollection(key=itemgetter(0))
        self.final_arrival_pointer = None
        self.chunks = SortedCollection(key=attrgetter('seq_start'))
        self.final_data_chunk = None

    def add(self, pkt):
        '''
        Merge the packet into the first chunk it overlaps with. If data was
        added to the end of a chunk, attempts to merge the next chunk (if there
        is one). This way, it is ensured that everything is as fully merged as
        it can be with the current data.

        Args:
        pkt = tcp.Packet
        '''
        if self.finished:
            raise RuntimeError('tried to add packets to a finished tcp.Direction')
        if self.chunks is None:
            raise RuntimeError('Tried to add packet to a tcp.Direction'
                               'that has been cleared')
        # discard packets with no payload. we don't care about them here
        if pkt.data == '':
            return
        # attempt to merge packet with existing chunks
        merged = False
        for i, chunk in enumerate(self.chunks):
            overlapped, (front, back) = chunk.merge(
                pkt, self.create_merge_callback(pkt))
            if overlapped:
                # check if this packet bridged the gap between two chunks
                if back and i < (len(self.chunks)-1):
                    overlapped2, result2 = chunk.merge(self.chunks[i+1])
                    # if the gap was bridged, the later chunk is obsolete
                    # so get rid of it.
                    if overlapped2:
                        self.chunks.remove(i+1)
                # if this is the main data chunk, calc final arrival
                if self.seq_start and chunk.seq_start == self.seq_start:
                    if front:
                        # packet was first in stream but is just now arriving
                        self.final_arrival_data.insert((self.seq_start, pkt.ts))
                    if back:  # usual case
                        self.final_arrival_data.insert(
                            (self.final_arrival_pointer, pkt.ts))
                    if not self.final_data_chunk:
                        self.final_data_chunk = chunk
                    self.final_arrival_pointer = self.final_data_chunk.seq_end
                merged = True
                break  # skip further chunks
        if not merged:
            # nothing overlapped with the packet
            # we need a new chunk
            self.new_chunk(pkt)

    @property
    def data(self):
        '''
        returns the TCP data, as far as it has been determined.
        '''
        if self.chunks is None:
            return None
        if self.final_data_chunk:
            return self.final_data_chunk.data
        else:
            if self.finished:
                return ''  # no data was ever added
            else:
                return None  # just don't know at all

    def clear_data(self):
        '''
        Drop data to save memory
        '''
        # we need to make sure we've grabbed any timing info we can
        if not self.finished:
            logging.warn('tried to clear data on an unfinished tcp.Direction')
        # clear the list, to make sure all chunks are orphaned to make it
        # easier for GC. hopefully.
        self.chunks.clear()
        self.chunks = None
        self.final_data_chunk = None

    @property
    def seq_start(self):
        '''
        starting sequence number, as far as we can tell now.
        '''
        if self.flow.handshake:
            assert(self in (self.flow.fwd, self.flow.rev))
            if self is self.flow.fwd:
                return self.flow.handshake[2].seq
            else:
                return self.flow.handshake[1].seq + 1
        elif self.finished:
            if self.chunks:
                return self.chunks[0].seq_start
            else:
                # this will also occur when a Direction with no handshake
                # has been cleared.
                logging.warning('getting seq_start from finished tcp.Direction '
                            'with no handshake and no data')
                return None
        else:
            return None

    def finish(self):
        '''
        Notifies the direction that there are no more packets coming. This means
        that self.data can be decided upon. Also calculates final_arrival for
        any packets that arrived while seq_start was None
        '''
        if settings.pad_missing_tcp_data:
            self.pad_missing_data()
        self.finished = True
        # calculate final_arrival
        if not self.final_arrival_data:
            peak_time = 0.0
            for vertex in self.arrival_data:
                if vertex[1].ts > peak_time:
                    peak_time = vertex[1].ts
                    self.final_arrival_data.insert((vertex[0], vertex[1].ts))

        if self.chunks and not self.final_data_chunk:
            self.final_data_chunk = self.chunks[0]

    def new_chunk(self, pkt):
        '''
        creates a new tcp.Chunk for the pkt to live in. Only called if an
        attempt has been made to merge the packet with all existing chunks.
        '''
        chunk = tcp.Chunk()
        chunk.merge(pkt, self.create_merge_callback(pkt))
        if self.seq_start and chunk.seq_start == self.seq_start:
            self.final_data_chunk = chunk
            self.final_arrival_pointer = chunk.seq_end
            self.final_arrival_data.insert((pkt.seq, pkt.ts))
        self.chunks.insert(chunk)

    def create_merge_callback(self, pkt):
        '''
        Returns a function that will serve as a callback for Chunk. It will
        add the passed sequence number and the packet to self.arrival_data.
        '''
        def callback(seq_num):
            self.arrival_data.insert((seq_num, pkt))
        return callback

    def byte_to_seq(self, byte):
        '''
        Converts the passed byte index to a sequence number in the stream. byte
        is assumed to be zero-based. Returns None if seq_start is None
        '''
        # TODO better handle case where seq_start is None
        seq_start = self.seq_start
        if seq_start is not None:
            return byte + seq_start
        else:
            return None

    def seq_arrival(self, seq_num):
        '''
        returns the packet in which the specified sequence number first arrived.
        '''
        try:
            return self.arrival_data.find_le(seq_num)[1]
        except ValueError:
            return None

    def byte_final_arrival(self, byte):
        return self.seq_final_arrival(self.byte_to_seq(byte))

    def seq_final_arrival(self, seq_num):
        '''
        Returns the time at which the seq number had fully arrived, that is,
        when all the data before it had also arrived.
        '''
        try:
            return self.final_arrival_data.find_le(seq_num)[1]
        except:
            return None

    def pad_missing_data(self):
        '''Pad missing data in the flow with zero bytes.'''
        if not self.chunks:
            return
        prev_chunk = self.chunks[0]
        for chunk in self.chunks[1:]:
            gap = chunk.seq_start - prev_chunk.seq_end
            if gap > 0:
                logging.info('Padding %d missing bytes at %d',
                             gap, prev_chunk.seq_end)
                first_chunk_pkt = self.seq_arrival(chunk.seq_start)
                chunk_ts = first_chunk_pkt.ts
                pad_pkt = packet.PadPacket(prev_chunk.seq_end, gap, chunk_ts)
                self.add(pad_pkt)
            prev_chunk = chunk
