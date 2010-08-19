#!/usr/bin/python

'''
Write the data from TCP flows in the indicated file
'''

import http, sys, dpkt, pcap

filename = 'fhs_ncomp.pcap'

pcap.WriteTCPFlowsFromFile(filename)
