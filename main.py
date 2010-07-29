#!/usr/bin/python

import dpkt, pcap
from pcaputil import *

reader = dpkt.pcap.Reader(open('fhs_ncomp.pcap','rb'))
flows = pcap.TCPFlowAccumulator(reader)

for k,v in flows.flowdict.iteritems():
    print friendly_socket(k), ', ', v
    if v.forward_data.startswith('GET /fhs/fhs.xsl'):
        #write it to a file
        f = open('output.txt','wb') # we don't want Python messing with the newlines
        f.write(v.reverse_data)
