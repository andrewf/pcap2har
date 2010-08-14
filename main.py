#!/usr/bin/python

import pcap
import os
import optparse
import logging
import sys
import http
from pcaputil import *

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

# read pcap file
reader = ModifiedReader(open(inputfile,'rb'))
flows = pcap.TCPFlowAccumulator(reader)

def try_call(function):
    '''
    returns a function that tries to call the passed function, but returns None
    if the function raises and exception.
    '''
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            return None
    return wrapped

# construct HTTPFlows, cleverly
# httpflows = an HTTPFlow for every TCPFlow that didn't cause an exception
#httpflows = map(try_call(http.HTTPFlow), flows.flowdict.itervalues())
#httpflows = filter(lambda v: bool(v), httpflows)
httpflows = []
for flow in flows.flowdict.itervalues():
    try:
        httpflow = http.HTTPFlow(flow)
        httpflows.append(httpflow)
    except ValueError:
        pass

# now get all pairs in one list, also cleverly
def add_pairs(old_pairs, flow):
    if flow.pairs:
        old_pairs += flow.pairs
    return old_pairs
all_pairs = reduce(add_pairs, httpflows, [])

pass
# write it out to outputfile