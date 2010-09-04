#!/usr/bin/python

'''
Main program that converts pcaps to HAR's.
'''

import pcap
import os
import optparse
import logging
import sys
import http
import httpsession
import har
import json

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
        httpflows.append(http.Flow(f))
    except http.Error as e:
        pass

# put all message pairs in one list
def combine_pairs(pairs, flow):
    return pairs + flow.pairs
pairs = reduce(combine_pairs, httpflows, [])

# parse HAR stuff
session = httpsession.HTTPSession(pairs)

with open(outputfile, 'w') as f:
    json.dump(session, f, cls=har.JsonReprEncoder, indent=2, encoding='utf8')

pass
