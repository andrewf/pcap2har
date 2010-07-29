#!/usr/bin/python

import dpkt, pcap, os, shutil
from pcaputil import *

reader = dpkt.pcap.Reader(open('fhs_ncomp.pcap','rb'))
flows = pcap.TCPFlowAccumulator(reader)

# write out the contents of flows to files in directory 'flowdata'
# get empty 'flowdata' directory
outputdirname = 'flowdata'
if os.path.exists(outputdirname):
    # delete it
    shutil.rmtree(outputdirname)
#create it
os.mkdir(outputdirname)

for i,v in enumerate(flows.flowdict.itervalues()):
    print i, ',', v
    # write forward data
    filename = os.path.join(outputdirname, 'flow%d-fwd.txt' % i)
    with open(filename, 'wb') as f:
        f.write(v.forward_data)
    # write reverse data
    filename = os.path.join(outputdirname, 'flow%d-rev.txt' % i)
    with open(filename, 'wb') as f:
        f.write(v.reverse_data)