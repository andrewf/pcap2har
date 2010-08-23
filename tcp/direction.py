from sortedcollection import SortedCollection
import tcp

class Direction:
    def __init__(self, flow):
        self.arrival_data = [] #[(seq_num, pkt)] # records when a given seq number first arrived
        self.final_arrival_data = None # or [(seq_num, dpkt_time)]
        self.closed_cleanly = False # until proven true
        self.chunks = [] # [TCPChunk] sorted by seq_start
        self.flow = flow # the parent TCPFlow. we need info from it
        self.seq_start= None # the seq number of the first byte of data, valid after finish() if self.data is valid
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
            self.seq_start = self.chunks[0].seq_start
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
        creates a new tcp.Chunk for the pkt to live in. Only called if an attempt
        has been made to merge the packet with all existing chunks
        '''
        chunk = tcp.Chunk()
        chunk.merge(pkt, self.create_merge_callback(pkt))
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
            self.arrival_data.append((seq_num, pkt))
        return callback
    def byte_to_seq(self, byte):
        '''
        Converts the passed byte index to a sequence number in the stream. byte
        is assumed to be zero-based.
        '''
        if self.seq_start:
            return byte + self.seq_start + 1
        else:
            return byte + self.flow.first_packet.seq

    def seq_arrival(self, seq_num):
        '''
        returns the packet in which the specified sequence number first arrived.
        self.arrival_data must be a SortedCollection at this point; self.finish()
        must have been called.
        '''
        if self.arrival_data:
            return self.arrival_data.find_le(seq_num)[1]
    def seq_final_arrival(self, seq_num):
        '''
        Returns the time at which the seq number had fully arrived. Will
        calculate final_arrival_data if it has not been already. Still requires
        self.arrival_data to be sorted by seq number, most likely a SortedCollection.
        '''
        if not self.final_arrival_data:
            self.calculate_final_arrivals()
        return self.final_arrival_data.find_le(seq_num)[1]
