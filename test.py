#!/usr/bin/python

'''
Write the data from TCP flows in the indicated file
'''

import http, sys, dpkt, pcap

filename = 'http.cap'

pcap.WriteTCPFlowsFromFile(filename)
