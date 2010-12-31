class Processor:
    '''
    Processes and interprets DNS packets.

    Call its `add` method with each dpkt.dns.DNS from the pcap.
    '''
    def __init__(self):
        self.packets = []
    def add(self, ts, pkt):
        self.packets.append((ts, pkt))
