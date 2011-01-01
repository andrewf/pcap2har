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
import tcp
from packetdispatcher import PacketDispatcher

# get cmdline args/options
parser = optparse.OptionParser(
    usage='usage: %prog inputfile outputfile [options]'
)
options, args = parser.parse_args()

# setup logs
logging.basicConfig(filename='pcap2har.log', level=logging.DEBUG)

# get filenames, or bail out with usage error
if len(args) == 2:
    inputfile, outputfile = args[0:2]
else:
    parser.print_help()
    sys.exit()

logging.info("Processing %s", inputfile)

# parse pcap file
dispatcher = PacketDispatcher()
pcap.ParsePcap(dispatcher, filename=inputfile)
dispatcher.finish()

# generate HTTP Flows
httpflows = []
flow_count = 0
for f in dispatcher.tcp.flowdict.itervalues():
    try:
        httpflows.append(http.Flow(f))
        flow_count += 1
    except http.Error as error:
        logging.warning(error)

# put all message pairs in one list
def combine_pairs(pairs, flow):
    return pairs + flow.pairs
pairs = reduce(combine_pairs, httpflows, [])

logging.info("Flows=%d. HTTP pairs=%d" % (flow_count,len(pairs)))
# parse HAR stuff
session = httpsession.HTTPSession(pairs)

with open(outputfile, 'w') as f:
    json.dump(session, f, cls=har.JsonReprEncoder, indent=2, encoding='utf8')

pass
