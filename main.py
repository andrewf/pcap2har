#!/usr/bin/python

import dpkt, pcap, os, shutil, optparse, pyper, logging
from pcaputil import *

# get cmdline args/options
parser = optparse.OptionParser()
parser.add_option('-d', '--directory', dest="dirname", default='flowdata', help="Directory to write flow files to.")
options, args = parser.parse_args()

# setup logs
logging.basicConfig(filename='pcap2har.log', level=logging.INFO)

filename = args[0]

# read pcap file
reader = ModifiedReader(open(filename,'rb'))
flows = pcap.TCPFlowAccumulator(reader)

# write out the contents of flows to files in directory 'flowdata'
# get empty 'flowdata' directory
outputdirname = options.dirname
if os.path.exists(outputdirname):
    # delete it
    shutil.rmtree(outputdirname)
# create it
os.mkdir(outputdirname)

#iterate through errors
for e in flows.errors:
    print 'error:', e

# iterate through flows
for i,v in enumerate(flows.flowdict.itervalues()):
    print i, ',', v
    # write data
    v.writeout_data(outputdirname + '/flow%d' % i)
    