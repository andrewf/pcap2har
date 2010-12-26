import dpkt
from pcaputil import *
from socket import inet_ntoa

import logging as log
import os
import shutil
import tcp
from packetdispatcher import PacketDispatcher


def ParsePcap(dispatcher, filename=None, reader=None):
    '''
    dispatcher = PacketDispatcher
    reader = pcaputil.ModifiedReader or None
    filename = filename of pcap file or None

    check for filename first; if there is one, load the reader from that. if
    not, look for reader.
    '''
    if filename:
        f = open(filename, 'rb')
        pcap = ModifiedReader(f)
    elif reader:
        pcap = reader
    else:
        raise 'function ParsePcap needs either a filename or pcap reader'
    #now we have the reader; read from it
    packet_count = 1 # start from 1 like Wireshark
    errors = [] # store errors for later inspection
    try:
        for record in pcap:
            ts = record[0]  # timestamp
            buf = record[1] # frame data
            hdr = record[2] # libpcap header
            # discard incomplete packets
            if hdr.caplen != hdr.len:
                # log packet number so user can diagnose issue in wireshark
                log.warning('ParsePcap: discarding incomplete packet, # %d' % packet_count)
            # parse packet
            try:
                # handle SLL packets, thanks Libo
                dltoff = dpkt.pcap.dltoff
                if pcap.dloff == dltoff[dpkt.pcap.DLT_LINUX_SLL]:
                    eth = dpkt.sll.SLL(pkt[1])
                # otherwise, for now, assume Ethernet
                else:
                    eth = dpkt.ethernet.Ethernet(buf)
                dispatcher.add(ts, buf, eth)
            # catch errors from this packet
            except dpkt.Error as e:
                errors.append((record, e, packet_count))
                log.warning(e)
    except dpkt.dpkt.NeedData as error:
        log.warning(error)
        log.warning('A packet in the pcap file was too short, '
                    'debug_pkt_count=%d' % debug_pkt_count)
        self.errors.append((None, error))

def TCPFlowsFromFile(filename):
    '''
    helper function for getting a TCPFlowAccumulator from a pcapfilename.
    Filename in, flows out. Intended to be used from the console.
    '''
    f = open(filename,'rb')
    reader = ModifiedReader(f)
    return TCPFlowAccumulator(reader)

def verify_file(filename):
    '''
    attempts to construct packets from all the packets in the file, to
    verify their validity, or dpkt's ability to interpret them. Intended to be
    used from the console.
    '''
    f = open(filename,'rb')
    reader = dpkt.pcap.Reader(f)
    i = 0
    for pkt in reader:
        try:
            eth = dpkt.ethernet.Ethernet(pkt[1])
        except dpkt.UnpackError:
            print 'error in packet #', i
            raise # let it hit the console
        i += 1

def WriteTCPFlowsFromFile(filename):
    '''
    takes a filename, parses the file with TCPFlowAccumulator, and writes the
    contents of all the flows to a directory "filename.d"
    '''
    flows = TCPFlowsFromFile(filename)
    output_dir = filename + ".d"
    # get clean directory
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.mkdir(output_dir)
    # write out data
    for i, f in enumerate(flows.flowdict.itervalues()):
        f.writeout_data(os.path.join(output_dir, str(i)))
