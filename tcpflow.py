from tcppacket import TCPPacket

class TCPFlow:
    '''assembles a series of tcp packets into streams of the actual data
    sent.

    Includes forward data (sent) and reverse data (received), from the
    perspective of the SYN-sender.'''
    def __init__(self, packets, ):
        '''assembles the series. packets is a list of TCPPacket's from the same
        socket.'''
        self.packets = packets
        # grab handshake, if possible
        # discover direction, etc.
        # synthesize forward data, backwards data
        forward_packets = [pkt for pkt in self.packets if self.samedir(pkt)]
        reverse_packets = [pkt for pkt in self.packets if not self.samedir(pkt)]
        forward_data = assemble_stream(forward_packets)
        reverse_data = assemble_stream(reverse_data)
        # calculate statistics?
