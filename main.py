#!/usr/bin/python

import pcap
import os
import optparse
import logging
import sys
import http

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

pass
