import gzip
import zlib
import cStringIO
from base64 import encodestring as b64encode
import logging

from .. import dpkt_http_replacement as dpkt_http
from ..mediatype import MediaType
from .. import settings

import common as http
import message

# try to import UnicodeDammit from BeautifulSoup,
# starting with system and defaulting to included version
# otherwise, set the name to None
try:
    try:
        from BeautifulSoup import UnicodeDammit
    except ImportError:
        from ..BeautifulSoup import UnicodeDammit
except ImportError:
    UnicodeDammit = None
    log.warning('Can\'t find BeautifulSoup, unicode is more likely to be '
                'misinterpreted')

class Response(message.Message):
    '''
    HTTP response.
    Members:
    * mediaType: mediatype.MediaType, constructed from content-type
    * mimeType: string mime type of returned data
    * body: http decoded body data, otherwise unmodified
    * text: body text, unicoded if possible, otherwise base64 encoded
    * encoding: 'base64' if self.text is base64 encoded binary data, else None
    * compression: string, compression type
    * original_encoding: string, original text encoding/charset/whatever
    * body_length: int, length of body, uncompressed if possible/applicable
    * compression_amount: int or None, difference between lengths of
      uncompressed data and raw data. None if no compression or we're not sure
    '''

    def __init__(self, tcpdir, pointer):
        message.Message.__init__(self, tcpdir, pointer, dpkt_http.Response)
        # get mime type
        if 'content-type' in self.msg.headers:
            self.mediaType = MediaType(self.msg.headers['content-type'])
        else:
            self.mediaType = MediaType('application/x-unknown-content-type')
        self.mimeType = self.mediaType.mimeType()
        # first guess at body size. handle_compression might
        # modify it, but this has to be before clear_body
        self.body_length = len(self.msg.body)
        self.compression_amount = None
        self.text = None
        # handle body stuff
        if settings.drop_bodies:
            self.clear_body()
        else:
            # uncompress body if necessary
            self.handle_compression()
            # try to get out unicode
            self.handle_text()

    def clear_body(self):
        '''
        Clear response body to save memory

        http.Flow has to do most of the work (after any other responses are
        parsed), here we just want to get rid of any references.
        '''
        self.body = self.raw_body = None
        self.msg.body = None

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
                    raise http.DecodingError('zlib failed to gunzip HTTP data')
                except:
                    # who knows what else it might raise
                    raise http.DecodingError(
                        'failed to gunzip HTTP data, don\'t know why')
            # handle deflate
            elif encoding == 'deflate':
                try:
                    # NOTE: wbits = -15 is a undocumented feature in python (it's
                    # documented in zlib) that gets rid of the header so we can
                    # do raw deflate. See: http://bugs.python.org/issue5784
                    self.body = zlib.decompress(self.raw_body, -15)
                except zlib.error:
                    raise http.DecodingError(
                        'zlib failed to undeflate HTTP data')
            elif encoding == 'compress' or encoding == 'x-compress':
                # apparently nobody uses this, so basically just ignore it
                self.body = self.raw_body
            elif encoding == 'identity':
                # no compression
                self.body = self.raw_body
            elif 'sdch' in encoding:
                # ignore sdch, a Google proposed modification to HTTP/1.1
                # not in RFC 2616.
                self.body = self.raw_body
            else:
                # I'm pretty sure the above are the only allowed encoding types
                # see RFC 2616 sec 3.5 (http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.5)
                raise http.DecodingError('unknown content-encoding token: ' + encoding)
        else:
            # no compression
            self.compression = 'identity'
            self.body = self.raw_body
        self.body_length = len(self.body)
        # comp_amount is 0 when no compression, which may or may not be to spec
        self.compression_amount = self.body_length - len(self.raw_body)

    def handle_text(self):
        '''
        Takes care of converting body text to unicode, if its text at all.
        Sets self.original_encoding to original char encoding, and converts body
        to unicode if possible. Must come after handle_compression, and after
        self.mediaType is valid.
        '''
        self.encoding = None
        # if the body is text
        if (self.mediaType and
            (self.mediaType.type == 'text' or
                (self.mediaType.type == 'application' and
                 'xml' in self.mediaType.subtype))):
            # if there was a charset parameter in HTTP header, store it
            if 'charset' in self.mediaType.params:
                override_encodings = [self.mediaType.params['charset']]
            else:
                override_encodings = []
            # if there even is data (otherwise,
            # dammit.originalEncoding might be None)
            if self.body != '':
                if UnicodeDammit:
                    # honestly, I don't mind not abiding by RFC 2023.
                    # UnicodeDammit just does what makes sense, and if the
                    # content is remotely standards-compliant, it will do the
                    # right thing.
                    dammit = UnicodeDammit(self.body, override_encodings)
                    # if unicode was found
                    if dammit.unicode:
                        self.text = dammit.unicode
                        self.originalEncoding = dammit.originalEncoding
                    else:
                        # unicode could not be decoded, at all
                        # HAR can't write data, but body might still
                        # be useful as-is
                        pass
                else:
                    # try the stupid version, just guess content-type or utf-8
                    u = None
                    # try our list of encodings + utf8 with strict errors
                    for e in override_encodings + ['utf8', 'iso-8859-1']:
                        try:
                            u = self.body.decode(e, 'strict')
                            self.originalEncoding = e
                            break  # if ^^ didn't throw, we're done
                        except UnicodeError:
                            pass
                    # if none of those worked, try utf8
                    # with 'replace' error mode
                    if not u:
                        # unicode has failed
                        u = self.body.decode('utf8', 'replace')
                        self.originalEncoding = None  # ???
                    self.text = u or None
        else:
            # body is not text
            # base64 encode it and set self.encoding
            # TODO: check with list that this is right
            self.text = b64encode(self.body)
            self.encoding = 'base64'

    @property
    def raw_body_length(self):
        if self.compression_amount is None:
            return self.body_length
        return self.body_length - self.compression_amount
