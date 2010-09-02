import dpkt
import urlparse
import gzip
import zlib
import cStringIO
import re
from mediatype import MediaType

# try to import UnicodeDammit from BeautifulSoup
# otherwise, set the name to None
try:
    from BeautifulSoup import UnicodeDammit
except ImportError:
    UnicodeDammit = None

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

class Response(Message):
    '''
    HTTP response.
    Members:
    * mediaType: mediatype.MediaType, constructed from content-type
    * mimeType: string mime type of returned data
    * body: http decoded body data, otherwise unmodified
    * body text, unicoded if possible, or None if the body is not text
    * compression: string, compression type
    * original_encoding: string, original text encoding/charset/whatever
    '''
    def __init__(self, tcpdir, pointer):
        Message.__init__(self, tcpdir, pointer, dpkt.http.Response)
        # uncompress body if necessary
        self.handle_compression()
        # get mime type
        if 'content-type' in self.msg.headers:
            self.mediaType = MediaType(self.msg.headers['content-type'])
            self.mimeType = self.mediaType.mimeType()
        else:
            self.mediaType = None
            self.mimeType = ''
        # try to get out unicode
        self.handle_text()
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

    def handle_text(self):
        '''
        Takes care of converting body text to unicode, if its text at all.
        Sets self.original_encoding to original char encoding, and converts body
        to unicode if possible. Must come after handle_compression, and after
        self.mediaType is valid.
        '''
        # if the body is text
        if self.mediaType.type == 'text' or \
                (self.mediaType.type == 'application' and 'xml' in self.mediaType.subtype):
            # if there was a charset parameter in HTTP header, store it
            if 'charset' in self.mediaType.params:
                override_encodings = [self.mediaType.params['charset']]
            else:
                override_encodings = []
            # if there even is data (otherwise, dammit.originalEncoding might be None)
            if self.body != '':
                if UnicodeDammit:
                    # honestly, I don't mind not abiding by RFC 2023. UnicodeDammit just
                    # does what makes sense, and if the content is remotely standards-
                    # compliant, it will do the right thing.
                    dammit = UnicodeDammit(self.body, override_encodings)
                    # if unicode was found
                    if dammit.unicode:
                        self.text = dammit.unicode
                        self.originalEncoding = dammit.originalEncoding
                    else:
                        # unicode could not be decoded, at all
                        # HAR can't write data, but body might still be useful as-is
                        pass
                else:
                    # try the braindead version, just guess content-type or utf-8
                    u = None
                    # try our list of encodings + utf8 with strict errors
                    for e in override_encodings + ['utf8', 'iso-8859-1']:
                        try:
                            u = self.body.decode(e, 'strict')
                            self.originalEncoding = e
                            break # if ^^ didn't throw, we're done
                        except UnicodeError:
                            pass
                    # if none of those worked, try utf8 with 'replace' error mode
                    if not u:
                        # unicode has failed
                        u = self.body.decode('utf8', 'replace')
                        self.originalEncoding = None # ???
                    self.text = u or None
        else:
            # body is not text
            self.text = None

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
