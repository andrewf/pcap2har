class Packet:
    '''
    A DNS packet, wrapped for convenience and with the pcap timestamp

    Members:
    ts = timestamp
    dns = dpkt.dns.DNS
    '''
    def __init__(self, ts, pkt):
        '''
        ts = pcap timestamp
        pkt = dpkt.dns.DNS
        '''
        self.ts= ts
        self.dns = pkt

class Query:
    '''
    A DNS question/answer conversation with a single ID

    Member:
    id = id that all packets must match
    started_ts = time of first packet
    last_ts = time of last known packet
    name = domain name
    '''
    def __init__(self, initial_packet, ts):
        '''
        initial_packet is simply the first one on the wire with a given ID.
        '''
        self.id = initial_packet.id
        self.started_time = ts
        self.last_ts = ts
    def add(self, pkt, ts):
        assert(pkt.id == self.id)

class Processor:
    '''
    Processes and interprets DNS packets.

    Call its `add` method with each dpkt.dns.DNS from the pcap.
    '''
    def __init__(self):
        self.packets = []
        self.queries = {}
    def add(self, ts, pkt):
        self.add_by_id(pkt)
        self.packets.append((ts, pkt))
    def add_by_id(self, pkt):
        '''
        adds the packet to self.by_id, which allows packets to be grouped by
        the requests or answers to which they are associated. I don't know how
        useful this is.
        '''
        if pkt.id in self.by_id:
            self.by_id[pkt.id].append(pkt)
        else:
            self.by_id[pkt.id] = [pkt]
