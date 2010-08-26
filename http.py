import dpkt
import urlparse
import gzip
import zlib
import cStringIO
import re

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
    Raised when HTTP cannot be parsed from the given data.
    '''
    pass

class DecodingError(HTTPError):
    '''
    Raised when encoded HTTP data cannot be decompressed/decoded/whatever.
    '''
    pass

class HTTPFlow:
    '''
    Parses a TCPFlow into HTTP request/response pairs. Or not, depending on the
    integrity of the flow. After __init__, self.pairs contains a list of
    MessagePair's. Requests are paired up with the first response that occured
    after them which has not already been paired with a previous request. Responses
    that don't match up with a request are ignored. Requests with no response are
    paired with None.
    '''
    def __init__(self, tcpflow):
        '''
        tcpflow = tcp.Flow
        '''
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
    * seq_start: first sequence number of the Message's data in the tcpdir
    * seq_end: first sequence number past Message's data (slice-style indices)
    * ts_start: when Message started arriving (dpkt timestamp)
    * ts_end: when Message had fully arrived (dpkt timestamp)
    * body_raw: body before compression is taken into account
    '''
    def __init__(self, tcpdir, pointer, msgclass):
        '''
        Args:
        tcpdir = tcp.Direction
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
        # get raw body
        self.raw_body = self.msg.body

class Request(Message):
    '''
    HTTP request. Parses higher-level info out of dpkt.http.Request
    Members:
    * query: Query string name-value pairs. {string: [string]}
    * host: hostname of server.
    * fullurl: Full URL, with all components.
    * url: Full URL, but without fragments. (that's what HAR wants)
    '''
    def __init__(self, tcpdir, pointer):
        Message.__init__(self, tcpdir, pointer, dpkt.http.Request)
        # get query string. its the URL after the first '?'
        uri = urlparse.urlparse(self.msg.uri)
        self.host = self.msg.headers['host'] if 'host' in self.msg.headers else ''
        fullurl = urlparse.ParseResult('http', self.host, uri.path, uri.params, uri.query, uri.fragment)
        self.fullurl = fullurl.geturl()
        self.url, frag = urlparse.urldefrag(self.fullurl)
        self.query = urlparse.parse_qs(uri.query)

# RE's for use on mime types
mimetype_text = re.compile('text/.+')
mimetype_image = re.compile('image/.+')

class Response(Message):
    '''
    HTTP response.
    Members:
    * mimeType: string mime type of returned data
    * body: http decoded body data
    * compression: string, compression type
    '''
    def __init__(self, tcpdir, pointer):
        Message.__init__(self, tcpdir, pointer, dpkt.http.Response)
        # get mime type
        if 'content-type' in self.msg.headers:
            self.mimeType= self.msg.headers['content-type']
        else:
            self.mimeType = ''
        self.handle_compression()
        # determine whether this is text
        self.istext = bool(mimetype_text.match(self.mimeType))
    def handle_compression(self):
        '''
        Sets self.body to the http decoded response data. Sets compression to
        the name of the compresson type.
        '''
        # if content-encoding is found
        if 'content-encoding' in self.msg.headers:
            encoding = self.msg.headers['content-encoding'].lower()
            self.compression = encoding
            # handle gzip
            if encoding == 'gzip' or encoding == 'x-gzip':
                try:
                    gzipfile = gzip.GzipFile(
                        fileobj = cStringIO.StringIO(self.raw_body)
                    )
                    self.body = gzipfile.read()
                except zlib.error:
                    raise DecodingError('zlib failed to gunzip HTTP data')
                except:
                    # who knows what else it might raise
                    raise DecodingError("failed to gunzip HTTP data, don't know why")
            # handle deflate
            elif encoding == 'deflate':
                try:
                    # NOTE: wbits = -15 is a undocumented feature in python (it's
                    # documented in zlib) that gets rid of the header so we can
                    # do raw deflate. See: http://bugs.python.org/issue5784
                    self.body = zlib.decompress(self.raw_body, -15)
                except zlib.error:
                    raise DecodingError('zlib failed to undeflate HTTP data')
            elif encoding == 'compress' or encoding == 'x-compress':
                # apparently nobody uses this, so basically just ignore it
                self.body = self.raw_body
            elif encoding == 'identity':
                # no compression
                self.body = self.raw_body
            else:
                # I'm pretty sure the above are the only allowed encoding types
                # see RFC 2616 sec 3.5 (http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.5)
                raise DecodingError('unknown content-encoding token: ' + encoding)
        else:
            # no compression
            self.compression = 'identity'
            self.body = self.raw_body
                

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
        curr_data = tcpdir.data[pointer:pointer+200]
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
    except dpkt.UnpackError as e:
        print 'failed to parse http: ', e
        return False, None, None
    else:
        return True, requests, responses
