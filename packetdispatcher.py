'''

'''

import dpkt
import tcp as tcpmodule

class PacketDispatcher:
    '''
    takes a series of dpkt.Packet's and calls callbacks based on their type

    For each packet added, picks it apart into its transport-layer packet type
    and --calls a registered callback, which usually just adds it to a handler
    for that type--.

    Actually, for now it's just going to add it to a tcp.FlowBuilder
    '''
    def __init__(self, flowbuilder):
        self.tcpflowbuilder= flowbuilder
    def add(self, ts, buf, eth):
        '''
        ts = dpkt timestamp
        buf = original packet data
        eth = dpkt.ethernet.Ethernet, whether its real Ethernet or from SLL
        '''
        #decide based on pkt.data
        # if it's IP...
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            # if it's TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                tcppkt = tcpmodule.Packet(ts, buf, eth, ip, tcp)
                self.tcpflowbuilder.add(tcppkt)
        # if it's UDP...
        elif isinstance(eth.data, dpkt.udp.UDP):
            #TODO: handle UDP packets
            pass

