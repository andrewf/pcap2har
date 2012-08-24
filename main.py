#!/usr/bin/python

'''
Main program that converts pcaps to HAR's.
'''

import os
import optparse
import logging
import sys
import json

from pcap2har import pcap
from pcap2har import http
from pcap2har import httpsession
from pcap2har import har
from pcap2har import tcp
from pcap2har import tls
from pcap2har import settings
from pcap2har.packetdispatcher import PacketDispatcher
from pcap2har.pcaputil import print_rusage


# get cmdline args/options
parser = optparse.OptionParser(
    usage='usage: %prog inputfile outputfile'
)
parser.add_option('--no-pages', action='store_false',
                  dest='pages', default=True)
parser.add_option('-d', '--drop-bodies', action='store_true',
                  dest='drop_bodies', default=False)
parser.add_option('-k', '--keep-unfulfilled-requests', action='store_true',
                  dest='keep_unfulfilled', default=False)
parser.add_option('-r', '--resource-usage', action='store_true',
                  dest='resource_usage', default=False)
parser.add_option('--pad_missing_tcp_data', action='store_true',
                  dest='pad_missing_tcp_data', default=False)
parser.add_option('--strict-http-parsing', action='store_true',
                  dest='strict_http_parsing', default=False)
parser.add_option('-l', '--log', dest='logfile', default='pcap2har.log')
parser.add_option('--nsskeylog', dest='keylog', default=None,
                  help = 'Log of SSL/TLS keys used in a browsing session. See '
                  'https://developer.mozilla.org/en-US/docs/NSS_Key_Log_Format '
                  'and the README for more details.')
options, args = parser.parse_args()

# copy options to settings module
settings.process_pages = options.pages
settings.drop_bodies = options.drop_bodies
settings.keep_unfulfilled_requests = options.keep_unfulfilled
settings.pad_missing_tcp_data = options.pad_missing_tcp_data
settings.strict_http_parse_body = options.strict_http_parsing

# setup logs
logging.basicConfig(filename=options.logfile, level=logging.INFO)

# get filenames, or bail out with usage error
if len(args) == 2:
    inputfile, outputfile = args[0:2]
elif len(args) == 1:
    inputfile = args[0]
    outputfile = inputfile+'.har'
else:
    parser.print_help()
    sys.exit()

logging.info('Processing %s', inputfile)

# open keylog file, if specified, and create a tls.SessionManager
if options.keylog:
    try:
        keylog = open(options.keylog)
        tls_session_manager = tls.session.SessionManager(keylog)
    except IOError:
        print >>sys.stderr, 'Failed to read keylog file', options.keylog
else:
    tls_session_manager = None

# parse pcap file
dispatcher = PacketDispatcher(tls_session_manager)
pcap.ParsePcap(dispatcher, filename=inputfile)
dispatcher.finish()

# parse HAR stuff
session = httpsession.HttpSession(dispatcher)

logging.info('Flows=%d. HTTP pairs=%d' % (len(session.flows), len(session.entries)))

#write the HAR file
with open(outputfile, 'w') as f:
    json.dump(session, f, cls=har.JsonReprEncoder, indent=2, encoding='utf8', sort_keys=True)

if options.resource_usage:
    print_rusage()
