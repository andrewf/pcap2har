#!/usr/bin/python

import dpkt, pcap
from pcaputil import *

reader = dpkt.pcap.Reader(open('fhs.pcap','rb'))
flows = pcap.TCPFlowAccumulator(reader)

for k,v in flows.flowdict.iteritems():
    print friendly_socket(k), ', ', v
