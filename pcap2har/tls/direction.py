# Copyright 2012 Google Inc.

from dpkt import ssl
from cStringIO import StringIO

class Direction(object):
    '''
    One side of an SSL flow.

    This class must track how much of the finally-arrived
    data we have already parsed into dpkt.SSL3* messages, and
    only parse new stuff when packets are added.

    Members:
    * tcpdir: tcp.Direction
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
        self._data = None

    def update_records(self):
        '''
        If data we haven't parsed yet has finally arrived in tcpdir,
        parse it, save it, and notify self.tls_state. Invalidate _data cache.
        Called by flow whenever packets are added.
        '''
        if (not (self.tcpdir.data is None)
                and self.parsed_bytes < len(self.tcpdir.data)):
            # parse the new material (may not consume all new data)
            new_data = self.tcpdir.data[self.parsed_bytes:]
            records, bytes_parsed = ssl.TLSMultiFactory(new_data)
            for rec in records:
                print 'new record'
                # add it to internal list of all packets this direction
                new_messages = self.tls_state.add_record(rec)
                for msg in new_messages:
                    #print 'new message: %r' % msg
                    # we could just add to app data here...
                    if isinstance(msg, ssl.TLSChangeCipherSpec):
                        # immediately switches over to new cipher state
                        self.on_change_cipher_spec()
            # update pointer
            self.parsed_bytes += bytes_parsed
            # invalidate cache
            self._data = None

    @property
    def data(self):
        #print 'pretending to decrypt data: "%s"' % `self.ciphertext[:300]`
        # join together the data segments from plaintext AppData records in
        # all tls_states
        print 'processing data'
        if self._data is None:
            sio = StringIO()
            for state in self.old_states + [self.tls_state]:
                print '  state'
                for msg in state.plaintext:
                    if isinstance(msg, ssl.TLSAppData):
                        print '   appdata'
                        sio.write(msg)
            self._data = sio.getvalue()
        print 'returning data %s...%s' % (repr(self._data[:15]),
                                          repr(self._data[-15:]))
        return self._data

    def on_change_cipher_spec(self):
        '''
        Switch to next connstate
        '''
        print 'switching connstate'
        if self.tls_state:
            print '  after first time'
            # self.tls_state starts None at construction, don't save that.
            self.old_states.append(self.tls_state)
        self.tls_state = self.flow.next_connstate(self)

    def byte_to_seq(self, byte):
        # this fn may be replaced by byte_final_arrival
        return self.tcpdir.byte_to_seq(byte)  # LIES!!

    def seq_final_arrival(self, seq):
        # this fn may be replaced by byte_final_arrival
        return self.tcpdir.seq_final_arrival(seq)  # MOAR LIES!
