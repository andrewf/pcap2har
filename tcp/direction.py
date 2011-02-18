from sortedcollection import SortedCollection
import tcp
from operator import itemgetter

class Direction:
    '''
    Represents data moving in one direction in a TCP flow.

    Members:
    * finished = bool. Indicates whether more packets should be expected
    * chunks = [tcp.Chunk], sorted by seq_start
    * flow = tcp.Flow, the flow to which the direction belongs
    * arrival_data = SortedCollection([(seq_num, pkt)])
    * final_arrival_data = SortedCollection([(seq_num, ts)])
    * final_data_chunk = Chunk or None, the chunk that contains the final data,
      only after seq_start is valid
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
        self.chunks = []
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
        # discard packets with no payload. we don't care about them here
        if pkt.data == '':
            return
        # attempt to merge packet with existing chunks
        merged = False
        for i, chunk in enumerate(self.chunks):
            overlapped, (front, back) = chunk.merge(pkt,
                                             self.create_merge_callback(pkt))
            if overlapped: # if the data overlapped
                # if data was added on the back and there is a chunk after this
                if back and i < (len(self.chunks)-1):
                    # try to merge with the next chunk as well
                    # in case that packet bridged the gap
                    overlapped2, result2 = chunk.merge(self.chunks[i+1])
                    if overlapped2: # if that merge worked
                        # data should only be added to back
                        assert( (not result2[0]) and (result2[1]))
                        del self.chunks[i+1] # remove the now-redundant chunk
                # if this is the main data chunk, calc final arrival
                if self.seq_start and chunk.seq_start == self.seq_start:
                    if back: # new data must be added to add new final arrival point
                        self.final_arrival_data.insert((self.final_arrival_pointer, pkt.ts))
                    if not self.final_data_chunk:
                        self.final_data_chunk = chunk
                    self.final_arrival_pointer = self.final_data_chunk.seq_end
                merged = True
                break # skip further chunks
        if not merged:
            # nothing overlapped with the packet
            # we need a new chunk
            self.new_chunk(pkt)
    @property
    def data(self):
        '''
        returns the TCP data, as far as it has been determined.
        '''
        if self.final_data_chunk:
            return self.final_data_chunk.data
        else:
            if self.finished:
                return '' # no data was ever added
            else:
                return None # just don't know at all
    @property
    def seq_start(self):
        '''
        starting sequence number, as far as we can tell now.
        '''
        if self.flow.handshake:
            if self is self.flow.fwd:
                return self.flow.handshake[2].seq
            elif self is self.flow.rev:
                return self.flow.handshake[1].seq + 1
            else:
                raise RuntimeError("holy crap, tcp.Direction has a flow it doesn't belong to")
        elif self.finished:
            if self.chunks:
                return self.chunks[0].seq_start
            else:
                log.warning('getting seq_start from finished tcp.Direction with no handshake and no data')
                return None
        else:
            return None
    def finish(self):
        '''
        Notifies the direction that there are no more packets coming. This means
        that self.data can be decided upon.
        '''
        self.finished = True
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
        self.chunks.append(chunk)
        self.sort_chunks() # it would be better to insert the packet sorted
    def sort_chunks(self):
        self.chunks.sort(key=lambda chunk: chunk.seq_start)
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
        is assumed to be zero-based.
        '''
        # TODO better hand case where seq_start is None
        seq_start = self.seq_start
        if seq_start is not None:
            return byte + seq_start
        else:
            return byte + self.flow.first_packet.seq
    def seq_arrival(self, seq_num):
        '''
        returns the packet in which the specified sequence number first arrived.
        self.arrival_data must be a SortedCollection at this point;
        self.finish() must have been called.
        '''
        return self.arrival_data.find_le(seq_num)[1]
    def seq_final_arrival(self, seq_num):
        '''
        Returns the time at which the seq number had fully arrived. Will
        calculate final_arrival_data if it has not been already. Only callable
        after self.finish()
        '''
        return self.final_arrival_data.find_le(seq_num)[1]
