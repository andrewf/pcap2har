#!/usr/bin/python

import dpkt, pcap

reader = dpkt.pcap.Reader(open('http.cap','rb'))
flows = pcap.TCPFlowAccumulator(reader)

for k, v in flows.flowdict.iteritems():
    print k, v
