#!/usr/bin/python

import pcap
import os
import optparse
import logging
import sys
import http
import har

# get cmdline args/options
parser = optparse.OptionParser(usage='usage: %prog inputfile outputfile [options]')
#parser.add_option('-d', '--directory', dest="dirname", default='flowdata', help="Directory to write flow files to.")
options, args = parser.parse_args()

# setup logs
logging.basicConfig(filename='pcap2har.log', level=logging.INFO)

# get filenames, or bail out with usage error
if len(args) == 2:
    inputfile, outputfile = args[0:2]
else:
    parser.print_help()
    sys.exit()

flows = pcap.TCPFlowsFromFile(inputfile)

# generate HTTP Flows
httpflows = []
for f in flows.flowdict.itervalues():
    try:
        httpflows.append(http.HTTPFlow(f))
    except http.HTTPError as e:
        pass

# put all message pairs in one list
def combine_pairs(pairs, flow):
    return pairs + flow.pairs
pairs = reduce(combine_pairs, httpflows, [])

# parse HAR stuff
session = har.HTTPSession(pairs)

pass
