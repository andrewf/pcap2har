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

# parse HAR stuff
session = httpsession.HttpSession(dispatcher)

logging.info("Flows=%d. HTTP pairs=%d" % (len(session.flows),len(session.entries)))

#write the HAR file
with open(outputfile, 'w') as f:
    json.dump(session, f, cls=har.JsonReprEncoder, indent=2, encoding='utf8')
