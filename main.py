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
logging.basicConfig(filename='pcap2har.log', level=logging.INFO)

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

dns = dispatcher.udp.dns
for q in dns.queries.itervalues():
    print '(%d) %s' % (dns.num_queries(q.name), q.name), '\tduration:', dns.get_resolution_time(q.name)

# parse HAR stuff
session = httpsession.HTTPSession(dispatcher)

logging.info("Flows=%d. HTTP pairs=%d" % (len(session.flows),len(session.entries)))

with open(outputfile, 'w') as f:
    json.dump(session, f, cls=har.JsonReprEncoder, indent=2, encoding='utf8')

pass
