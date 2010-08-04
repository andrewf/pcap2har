#!/usr/bin/python

'''
Runs through the directory passed on the command line, looks for pcap files
recursively, and compares the outputs of the tcp flows to see how well each
program did.
'''

import dpkt, pcap, os, shutil, optparse, pyper, sys
from pcaputil import *

class InconsistentAnalyses(Exception):
    '''
    raised when the analyses of the same file are inconsistent.
    pass filename, socket, and bool for whether data was forward'''
    pass

def writeout_bad_data(one, two, filename):
    '''
    writes the two data streams to a pair of files, named after the given base
    name. used for writing out two inconsistent streams to see where there
    errors are.
    '''
    # write first stream
    with open(filename + "-one.dat", 'wb') as f:
        f.write(one)
    with open(filename + "-two.dat", 'wb') as f:
        f.write(two)
    

def compare_progs(filename):
    '''
    Takes a filename and runs it through both pcap parsers, and compares the
    contents of the flows, after they're sorted by socket.
    '''
    print 'comparing file', filename
    # read with pcap2har
    reader = dpkt.pcap.Reader(open(filename,'rb'))
    flows = pcap.TCPFlowAccumulator(reader) # flows are in flows.flowdict
    # read with WaterfallAnalysis
    pcapfile = open(filename, 'rb')
    waterfall = pyper.WaterfallAnalysis(pcapfile) #flows are in waterfall.tcp_flows :: [pyper.TCPFlow]
    # see if the numbers of flows are the same, otherwise log it
    if len(waterfall.tcp_flows) != len(flows.flowdict):
        print 'analyses of file \"%s\" do not have the same number of flows' % filename
    # iter through waterfall.tcpflows, and compare flows with flows.flowdict[current.socket]
    for flow in waterfall.tcp_flows:
        socket = flow.socket
        # see if there is a corresponding flow in flows.flowdict
        if socket in flows.flowdict:
            flow2 = flows.flowdict[socket] # the flow from pcap2har
            # compare flow.forward_data and flow2.forward_data
            if flow.forward_data != flow2.forward_data:
                print 'discrepancy found in forward data for file \"%s\", socket %s' % (filename, friendly_socket(socket))
                writeout_bad_data(flow.forward_data, flow2.forward_data, 'baddata-fwd')
                writeout_bad_data(flow.reverse_data, flow2.reverse_data, 'baddata-rev')
                raise InconsistentAnalyses(filename, socket, True)
            # compare flow.reverse_data and flow2.reverse_data
            if flow.reverse_data != flow.forward_data:
                print 'discrepancy found in reverse data for file \"%s\", socket %s' % (filename, friendly_socket(socket))
                writeout_bad_data(flow.forward_data, flow2.forward_data, 'baddata-fwd')
                writeout_bad_data(flow.reverse_data, flow2.reverse_data, 'baddata-rev')
                raise InconsistentAnalyses(filename, socket, False)
                
    

# get cmdline args/options
#~ parser = optparse.OptionParser()
#~ parser.add_option('-d', '--directory', dest="dirname", help="Directory to write flow files to.")
#~ options, args = parser.parse_args()

# get empty 'flowdata' directory
#~ outputdirname = options.dirname
#~ if os.path.exists(outputdirname):
    #~ # delete it
    #~ shutil.rmtree(outputdirname)
#~ # create it
#~ os.mkdir(outputdirname)

def main():
    '''
    walks through the directory from the command-line, and calls compare on
    pcap files found
    '''
    # startdir = args[0] or '.'
    startdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    for d in os.walk(startdir):
        for f in d[2]: # iterate through files in the directory
            # check if filename is valid pcap (ends with .cap or .pcap)
            if not (f.endswith('.pcap') or f.endswith('.cap')):
                continue
            # parse it by full name relative to working dir
            fullname = os.path.join(d[0], f)
            try:
                compare_progs(fullname)
            except InconsistentAnalyses as e:
                # exit
                print 'exiting program after parsing', fullname
                sys.exit()
    

if __name__ == '__main__':
    main()
