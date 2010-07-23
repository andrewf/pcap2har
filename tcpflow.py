from tcppacket import TCPPacket
import tcpseq

class TCPFlow:
    '''assembles a series of tcp packets into streams of the actual data
    sent.

    Includes forward data (sent) and reverse data (received), from the
    perspective of the SYN-sender.'''
    def __init__(self, packets, ):
        '''assembles the series. packets is a list of TCPPacket's from the same
        socket. They should be in order of transmission, otherwise there will
        probably be bugs.'''
        self.packets = packets
        # grab handshake, if possible
        # discover direction, etc.
        # synthesize forward data, backwards data
        forward_packets = [pkt for pkt in self.packets if self.samedir(pkt)]
        reverse_packets = [pkt for pkt in self.packets if not self.samedir(pkt)]
        forward_data = self.assemble_stream(forward_packets)
        reverse_data = self.assemble_stream(reverse_data)
        # calculate statistics?

    def assemble_stream(packets):
        '''does the actual stitching of the passed packets into data.'''
        # store tuples of format; ((seq_begin, seq_end), data_str)
        # when a new packet's data overlaps with one, pull that out, merge
        # them, and replace it.
        def collides(one, two):
            '''returns whether two data tuples are candidates for merging,
            that is, whether they overlap or touch'''
            seqone = one[0]
            seqtwo = two[0]
    	    if (seqtwo[0] <= seqone[0] and seqone[0] <= seqtwo[1]) or \
    	          (seqone[0] <= seqtwo[0] and seqtwo[0] <= seqone[1]):
    	       return True
    	    return False
    	def merge(old, new):
    	    '''merges the two data tuples into one.

    	    if one and two collide, will return merged data
    	    if they don't collide, return None

    	    if there is new data, second return is the initial new sequence
    	    number, otherwise (one was totally inside the other) None'''
    	    if not collides(old, new):
    	        return None, None
    	    else:
    	        #merge them
    	        #if new is completely inside old, return (old, None)
