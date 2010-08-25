import dpkt

def find_index(f, seq):
    '''
    returns the index of the first item in seq for which predicate f returns
    True. If no matching item is found, LookupError is raised.
    '''
    for i, item in enumerate(seq):
        if f(item):
            return i
    raise LookupError('no item was found in the sequence that matched the predicate')

class HTTPError(Exception):
    '''
    Thrown when HTTP cannot be parsed from the given data.
    '''
    pass

class HTTPFlow:
    '''
    Parses a TCPFlow into HTTP request/response pairs. Or not, depending on the
    integrity of the flow. After __init__, self.pairs, 
    '''
    def __init__(self, tcpflow):
        # try parsing it with forward as request dir
        success, requests, responses = parse_streams(tcpflow.fwd, tcpflow.rev)
        if not success:
            success, requests, responses = parse_streams(tcpflow.rev, tcpflow.fwd)
            if not success:
                # flow is not HTTP
                raise HTTPError('TCPFlow does not contain HTTP')
        # match up requests with nearest response that occured after them
        # first request is the benchmark; responses before that are irrelevant for now
        self.pairs = []
        try:
            # find the first response to a request we know about, that is, the first response after the first request
            first_response_index = find_index(lambda response: response.ts_start > requests[0].ts_start, responses)
            # these are responses that match up with our requests
            pairable_responses = responses[first_response_index:]
            if len(requests) > len(pairable_responses): # if there are more requests than responses
                # pad responses with None
                pairable_responses.extend( [None for i in range(len(requests) - len(pairable_responses))] )
            # if there are more responses, we would just ignore them anyway, which zip does for use
            # create MessagePair's
            for req, resp in zip(requests, responses):
                self.pairs.append(MessagePair(req, resp))
        except LookupError:
            # there were no responses after the first request
            # there's nothing we can do
            pass

class Message:
    '''
    Contains a dpkt.http.Request/Response, as well as other data required to
    build a HAR, including (mostly) start and end time.

    * msg: underlying dpkt class
    * data_consumed: how many bytes of input were consumed
    * start_time
    * end_time
    '''
    def __init__(self, tcpdir, pointer, msgclass):
        '''
        Args:
        tcpdir = TCPDirection
        pointer = position within tcpdir.data to start parsing from. byte index
        msgclass = dpkt.http.Request/Response
        '''
        # attempt to parse as http. let exception fall out to caller
        self.msg = msgclass(tcpdir.data[pointer:])
        self.data = self.msg.data
        self.data_consumed = (len(tcpdir.data) - pointer) - len(self.data)
        # calculate sequence numbers of data
        self.seq_start = tcpdir.byte_to_seq(pointer)
        self.seq_end = tcpdir.byte_to_seq(pointer + self.data_consumed) # past-the-end
        # calculate arrival_times
        self.ts_start = tcpdir.seq_final_arrival(self.seq_start)
        self.ts_end = tcpdir.seq_final_arrival(self.seq_end - 1)

class Request(Message):
    '''
    HTTP request.
    '''
    def __init__(self, tcpdir, pointer):
        Message.__init__(self, tcpdir, pointer, dpkt.http.Request)

class Response(Message):
    '''
    HTTP response.
    '''
    def __init__(self, tcpdir, pointer):
        Message.__init__(self, tcpdir, pointer, dpkt.http.Response)

class MessagePair:
    '''
    An HTTP Request/Response pair/transaction/whatever. Loosely corresponds to
    a HAR entry.
    '''
    def __init__(self, request, response):
        self.request = request
        self.response = response

def gather_messages(MessageClass, tcpdir):
    '''
    Attempts to construct a series of MessageClass objects from the data. The
    basic idea comes from pyper's function, HTTPFlow.analyze.gather_messages.
    Args:
    MessageClass = class, Request or Response
    tcpdir = TCPDirection, from which will be extracted the data
    '''
    messages = [] # [MessageClass]
    pointer = 0 # starting index of data that MessageClass should look at
    while pointer < len(tcpdir.data):
        msg = MessageClass(tcpdir, pointer)
        messages.append(msg)
        pointer += msg.data_consumed
    return messages

def parse_streams(request_stream, response_stream):
    '''
    attempts to construct dpkt.http.Request/Response's from the corresponding
    passed streams. Failure may either mean that the streams are malformed or
    they are simply switched
    Args:
    request_stream, response_stream = TCPDirection
    Returns:
    True or False, whether parsing succeeded
    request list or None
    response list or None
    '''
    try:
        requests = gather_messages(Request, request_stream)
        responses = gather_messages(Response, response_stream)
    except dpkt.UnpackError:
        return False, None, None
    else:
        return True, requests, responses
