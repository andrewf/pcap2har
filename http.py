import dpkt

class HTTPFlow:
    '''
    Parses a TCPFlow into HTTP request/response pairs. Or not, depending on the
    integrity of the flow.
    '''
    def __init__(self, tcpflow):
        # try parsing it with forward as request dir
        success, requests, responses = parse_streams(tcpflow.fwd, tcpflow.rev)
        if not success:
            success, requests, responses = parse_streams(tcpflow.rev, tcpflow.fwd)
            if not success:
                # flow is not HTTP
                raise ValueError('TCPFlow does not contain HTTP')
        # we have requests/responses. store them
        self.requests = requests
        self.responses = responses
        if len(requests) == len(responses):            
            self.pairs = zip(requests, responses)
        elif len(requests) > len(responses):
            #pad responses with None
            responses += [None for i in range(len(requests) - len(responses))]
            self.pairs = zip(requests, responses)
        else:
            self.pairs = None

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
    Args
    MessageClass = class, Request or Response
    tcpdir = TCPDirection, from which will be extracted the data
    '''
    messages = [] # [MessageClass]
    pointer = 0
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
