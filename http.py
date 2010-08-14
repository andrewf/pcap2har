import dpkt

class HTTPFlow:
    '''
    Parses a TCPFlow into HTTP request/response pairs. Or not, depending on the
    integrity of the flow.
    '''
    def __init__(self, tcpflow):
        # try parsing it with forward as request dir
        success, requests, responses = parse_streams(tcpflow.fwd.data, tcpflow.rev.data)
        if not success:
            success, requests, responses = parse_streams(flow.rev.data, flow.fwd.data)
            if not success:
                # flow is not HTTP
                raise ValueError('TCPFlow does not contain HTTP')
        # we have requests/responses; check and store
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

def gather_messages(MessageClass, data):
    '''
    Attempts to construct a series of MessageClass objects from the data. The
    basic idea comes from pyper's function, HTTPFlow.analyze.gather_messages.
    data = string
    '''
    messages = [] # MessageClass[]
    curr_data = data
    while len(curr_data):
        msg = MessageClass(curr_data) # if it fails, let the exception fall out to the caller
        messages.append(msg)
        curr_data = msg.data # remaining messages, if any, were stored in the previous message's data
    return messages

def parse_streams(request_stream, response_stream):
    '''
    attempts to construct dpkt.http.Request/Response's from the corresponding
    passed streams. Failure may either mean that the streams are malformed or
    they are simply switched
    Returns:
    True or False, whether parsing succeeded
    request list or None
    response list or None
    '''
    try:
        requests = gather_messages(dpkt.http.Request, request_stream)
        responses = gather_messages(dpkt.http.Response, response_stream)
    except dpkt.UnpackError:
        return False, None, None
    else:
        return True, requests, responses
