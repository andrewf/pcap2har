# Copyright 2012 Google Inc. All Rights Reserved.

'''
A flow using SSL or TLS encryption
'''
import logging
from .direction import Direction
from dpkt import ssl
import connectionstate


class Flow(object):
    '''
    Encrypted data flow.

    Takes a tcp.Flow and wraps it in a compatible interface that
    exposes the decrypted data. To do this right, efficiently, it needs
    to parse the SSL data progressively as it attains final arrival,
    not just packet-by-packet, and not just after .finish() either. How
    this works is, after each add(), each Direction looks to see if it has
    new data, and if it does, parses it using SSLMultiFactory, stores the
    packets, and also sends them back to Flow, in case they're Handshake
    or other whole-flow-relevant messages.

    Members:
    * fwd: ssl.Direction
    * rev: ssl.Direction
    * blackhole: whether to ignore all new records. Turned on in case of TLS
        error. Also implies fwd and rev have been cleared. Still pass packets to
        tcp.flow, in case a new flow starts on this socket.
    * tcpflow: tcp.Flow
    * connstate: connectionstate.Period, connection state to
        which packets are currently being added (starts None, set by
        next_connstate)
    * pending_params: connectionstate.Params, settings
        for connection state to come
    * pending_connstate: connectionstate.Period or None. None until
        self.fwd or rev asks for the next connection state, and set back to None
        when the other one asks for it. Serves as a flag for whether
    * old_states: [connectionstate.Period], states which have been killed
        by ChangeCipherSpec.
    '''

    # should be constructible with tcp.Flow with packets, for
    # after-the-fact decryption?
    def __init__(self, tcpflow, session_manager):
        self.tcpflow = tcpflow
        self.session_manager = session_manager
        # connstate and pending_connstate will be set for the first time
        # by the Directions when they call next_connstate to get their
        # first connection states
        self.pending_params = connectionstate.Params(None, None) # fill in later
        self.blackhole = False
        self.connstate = None
        self.pending_connstate = None
        self.old_states = []
        # create Directions, initialize connstate
        self.fwd = Direction(self, tcpflow.fwd)
        self.rev = Direction(self, tcpflow.rev)
        self.fwd.on_change_cipher_spec()
        self.rev.on_change_cipher_spec()

    def update_records(self):
        if not self.blackhole:
            try:
                self.fwd.update_records()
                self.rev.update_records()
            except ssl.SSL3Exception, e:
                self.blackhole = True
                # CLEAR FWD AND REV
                logging.warning('Blackholing SSL/TLS flow due to error: %r' % e)

    def add(self, pkt):
        self.tcpflow.add(pkt)  # also updates the tcpdirs owned by self.fwd/rev
        self.update_records()

    def next_connstate(self, asking_dir):
        '''
        Returns (the appropriate side of) self.pending_connstate

        Args:
        * asking_dir, the tls.Direction asking for the connstate, used to
            determine which side to return.
        '''
        assert(asking_dir in (self.fwd, self.rev))
        # helper fn to return correct Plex from self.pending_connstate
        def right_plex():
            if asking_dir is self.fwd:
                return self.pending_connstate.fwd
            return self.pending_connstate.rev
        # assume each dir asks for the pending connstate exactly once.
        # set var ret to the Plex to return
        if self.pending_connstate:
            ret = right_plex()
            self.pending_connstate = None
        else:
            # create pending_connstate, reset everything for next one
            # assume fwd is read from server perspective, for now.
            self.pending_connstate = connectionstate.Period(self.connstate,
                                                            self.session_manager)
            if self.connstate is not None:
                self.old_states.append(self.connstate)
            self.connstate = self.pending_connstate  # yes, this is weird
            self.pending_params = connectionstate.Params(None, None)
            ret = right_plex()
        return ret

    @property
    def handshake(self):
        return self.tcpflow.handshake

    def finish(self):
        self.tcpflow.finish()
        self.update_records()
