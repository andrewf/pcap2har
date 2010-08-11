#!/usr/bin/python

'''
Try parsing HTTP from the TCPFlow data in the files indicated on the command
line.
'''

import http, sys, dpkt

inputbasename = sys.argv[1]

forwarddata = None
reversedata = None

with open(inputbasename + '-fwd.dat','rb') as f:
    forwarddata = f.read()
with open(inputbasename + '-rev.dat','rb') as f:
    reversedata = f.read()

requests_are_forward = True


# try parsing with forward as request direction
success, requests, responses = parse_streams(forwarddata, reversedata)
if not success:
    # try parsing with reverse as request dir
    print 'parsing with reverse data as requests'
    success, requests, responses = parse_streams(reversedata, forwarddata)
    if not success:
        # well, crap
        print 'flow is not http, aborting'
        sys.exit()

# okay, hopefully everything is parsed now
if not len(requests) == len(responses):
    print 'different numbers of requests and responses'

pairs = zip(requests, responses)

# print it all out