# Copyright 2012 Google Inc.

from dpkt import ssl
from operator import itemgetter
from ..sortedcollection import SortedCollection
from cStringIO import StringIO

class Direction(object):
    '''
    One side of an SSL flow. Conforms to tcp.Direction interface.

    This class must track how much of the finally-arrived
    data we have already parsed into dpkt.ssl.TLS* messages, and
    only parse new stuff when packets are added.

    Members:
    * tcpdir: tcp.Direction
    * tls_state: connectionstate.ConnStatePlex, this side of the current
       connection state.
    * old_states: [ConnStatePlex], ConnStatePlex's that have been
       obsoleted by ChangeCipherSpec's.
    * parsed_bytes: how many bytes of tcpdir.data have been turned into
        TLSRecords so far.
    * timing_data: SortedCollection([(byte, ts)]), where ts is the time at which
        byte arrived, and all the bytes after it up to the next one.
    '''
    def __init__(self, flow, tcpdir):
        '''
        Args:
        * flow: ssl.Flow this belongs to
        * tcpdir: tcp.Direction that this obj will work with
        * tls_state: connectionstate.ConnStatePlex, where we stick
            parsed records and get decrypted records. Starts None; flow will
            call on_change_cipher_spec to set it up once both flow.fwd and
            flow.rev exist.
        * parsed_bytes: number of bytes of tcpdir.data that have been parsed
            into TLSRecords
        * old_states: [ConnStatePlex], it's easier for each Direction to keep
            its own list of Plex's to get data out of, rather than fishing the
            right ones out from self.flow
        * _data: cache for self.data
        '''
        self.flow = flow
        self.tcpdir = tcpdir
        self.tls_state = None
        self.parsed_bytes = 0
        self.app_data = []
        self.old_states = []
        self.timing_data = SortedCollection(key=itemgetter(0))
        self._data = StringIO()

    def update_records(self):
        '''
        If data we haven't parsed yet has finally arrived in tcpdir,
        parse it, save it, and notify self.tls_state. Invalidate _data cache.
        Called by flow immediately whenever packets are added.

        Arg:
          ts: dpkt timestamp, when the packet that triggered this call finally
            arrived. This works because there is only any new data if the
            packet triggered final arrival of new data.
        '''
        if (not (self.tcpdir.data is None)
                and self.parsed_bytes < len(self.tcpdir.data)):
            # parse the new material (may not consume all new data)
            new_data = self.tcpdir.data[self.parsed_bytes:]
            records, bytes_parsed = ssl.TLSMultiFactory(new_data)
            for rec in records:
                #print 'new record', rec.type
                # add it to internal list of all packets this direction
                new_messages = self.tls_state.add_record(rec)
                for msg in new_messages:
                    if isinstance(msg, ssl.TLSChangeCipherSpec):
                        # immediately switches over to new cipher state
                        self.on_change_cipher_spec()
                    elif isinstance(msg, ssl.TLSAppData):
                        # record the data and the timing (_data is always
                        # written at the end, so tell() gives its length)
                        # may not be accurate without seq_start, since pointer
                        # will be 0 and then we'll read several packets...
                        ts = self.tcpdir.byte_final_arrival(self.parsed_bytes)
                        self.timing_data.insert((self._data.tell(), ts))
                        self._data.write(msg)   # AppData is a string
            # update pointer
            self.parsed_bytes += bytes_parsed

    @property
    def data(self):
        if self._data is None:
            return None
        return self._data.getvalue()

    def clear_data(self):
        '''
        Clear out any data possible, to save memory.

        In conformance with tcp.Direction interface. First call clear_data
        on self.tcpdir, then get rid of data in 
        '''
        self.tcpdir.clear_data()
        self._data = None
        # wipe out tls_state


    def on_change_cipher_spec(self):
        '''
        Switch to next connstate
        '''
        #print 'switching connstate'
        if self.tls_state:
            #print '  after first time'
            # self.tls_state starts None at construction, don't save that.
            self.old_states.append(self.tls_state)
        self.tls_state = self.flow.next_connstate(self)
        #print '  new state %r' % self.tls_state.params.cipher_suite.name

    def byte_final_arrival(self, byte):
        return self.timing_data.find_le(byte)[1]
