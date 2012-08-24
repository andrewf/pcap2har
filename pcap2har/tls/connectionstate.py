# Copyright 2012 Google Inc. All Rights Reserved.

'''
Classes relating to TLS connection states
'''

import logging

import dpkt
import dpkt.ssl
from . import decryptors
from . import decompressors


class ReadState(object):
    '''
    Contains the various bits of state needed to process TLSRecord's

    Includes decryption state, compression state, and maybe someday MAC
    state. This is state specific to one side of a TLS duplex connection,
    e.g., you'll need two of these to decrypt a whole connection.

    Members:
    * params: Params
    * compression_state: None, or some compressor
    * cipher_state: depends on cipher suite
    * client_perspective: bool, whether we're reading from client_perspective
        or server perspective
    '''

    def __init__(self, params, client_perspective):
        '''
        Get together some state based on Params
        '''
        self.client_perspective = client_perspective
        self.params = params
        self.decryptor = decryptors.new(params, client_perspective)
        self.decompressor = decompressors.new(params.compression)
        # depending on params.cipher_suite, fill out other state

    def process_record(self, record):
        '''
        Take encrypted and compressed record, return plaintext
        '''
        return self.decompress_record(self.decrypt_record(record))

    def decompress_record(self, record):
        '''
        Turn TLSCompressed to TLSPlaintext

        Take TLSRecord with compressed=True, return new one with False
        '''
        decomp = self.decompressor.decompress(record.data)
        return dpkt.ssl.TLSRecord(
                        type=record.type,
                        compressed=False,
                        encrypted=False,
                        data=decomp)

    def decrypt_record(self, record):
        '''
        Turn TLSCiphertext to TLSCompressed

        Take TLSRecord with encrypted=True, return new one with False. Also
        strips off and ignores the MAC.
        '''
        plaintext = self.decryptor.decrypt(record.data)
        #print 'plaintext: %s...%s' % (`plaintext[:15]`, `plaintext[-15:]`)
        return dpkt.ssl.TLSRecord(
                        type=record.type,
                        encrypted=False,
                        compressed=True,  # we assume, based on spec
                        data=plaintext)


class Params(object):
    '''
    Various parameters needed to start a State

    The biggest ones are the cipher suite and, if available, the master
    secret. We also need to know whether we're reading from the client
    or server perspective. These parameters will generally be derived from
    the previous Period.

    Members:
    * version: int, TLS Version, 0 for SSL3, 1 for TLS 1.0, etc
    * cipher_suite: dpkt.ssl_ciphersuites.CipherSuite
    * compression: compression algo as int
    * master_secret: string or None
    * client_random: string or None
    * server_random: string or None
    '''

    def __init__(self, version, cipher_suite, **kwargs):
        self.version = version
        self.cipher_suite = cipher_suite or dpkt.ssl_ciphersuites.BY_CODE[0x00]
        self.master_secret = kwargs.get('master_secret')
        self.compression = kwargs.get('compression', 0)
        self.client_random = kwargs.get('client_random')
        self.server_random = kwargs.get('server_random')


class Plex(object):
    '''
    One side of a Period. One plex, as opposed to duplex.

    Stores a list of TLSEncrypted, and incrementally decrypt them
    (using self.read_state) into a plaintext stream. Then incrementally
    parse this into a list of inner TLS messages; handshake, appdata, etc.
    Passes them through to Period, which figures out period-wide
    info from them.

    Can't instantiate read_state until we know whether we're reading from
    a client or server perspective. This must either be passed in through
    __init__ or guessed from passage of Server or Client Hellos. The exception
    is when params is None

    Members:
    * period: Period that owns this.
    * client_perspective: bool or None, depending on whether it's known.
    * params: Params, for read_state
    * read_state: ReadState, state for decryption, etc.
    * encrypted: [TLSRecord], incoming encrypted records
    * records_decrypted: int, number of records in self.encrypted that
        have been incrementally decrypted so far.
    * plaintext: [TLS Message], decrypted messages.
    * plaintext_residue: leftover plaintext that doesn't make a whole
        message.
    * plaintext_residue_type: int message type from TLSRecord that produced
        plaintext_residue, or None.
    '''

    def __init__(self, period, params, client_perspective):
        self.period = period
        self.params = params
        self.read_state = None
        self.client_perspective = client_perspective
        self.encrypted = []
        self.records_decrypted = 0
        self.plaintext = []
        self.plaintext_residue = ''
        #if self.client_perspective:
        #    self.read_state = ReadState(self.params, client_perspective)

    def add_record(self, record):
        '''
        Add an encrypted record to list, update other state.

        Returns any new plaintext messages that result.
        '''
        #print 'adding record of type %d' % record.type
        self.encrypted.append(record)
        return self.update_plaintext()

    def update_plaintext(self):
        '''
        Updates the list of TLS messages based on the new Records.

        Call after adding new records. Returns the new messages.
        '''
        # make sure read_state is usable
        if not self.read_state:
            if self.client_perspective is not None:
                self.read_state = ReadState(self.params,
                                            self.client_perspective)
            else:
                # nothing we can do here
                return []
        # decrypt any new records
        #print 'updating plaintext with records'
        if len(self.encrypted) > self.records_decrypted:
            new_records = map(self.read_state.process_record,
                              self.encrypted[self.records_decrypted:])
            self.records_decrypted += len(new_records)
            new_messages = []
            for rec in new_records:
                #print '  update_plaintext: new record:', repr(rec.length)
                # if there is plaintext residue, make sure its type matches with
                # the current record.
                if (self.plaintext_residue and
                    self.plaintext_residue_type != rec.type):
                    # if this happens, a record probably got dropped somehow.
                    # we're probably toast from a crypto state standpoint, but
                    # the best thing we can do is start fresh.
                    logging.warning(
                        'TLS record fragment type mismatch, ignoring old fragment.')
                    self.plaintext_residue = ''
                # parse as many messages as you can, stopping on NeedData and
                # saving the residue/residue type
                plaintext = self.plaintext_residue + rec.data
                pointer = 0
                end = len(plaintext)
                klass = dpkt.ssl.RECORD_TYPES.get(rec.type)
                if not klass:
                    raise RuntimeError('Invalid TLS record type %d.' % rec.type)
                #print '  parsing record data:', locals()
                while pointer < end:
                    try:
                        #print '   parsing new message'
                        new_message = klass(plaintext[pointer:])
                        pointer += len(new_message)
                        new_messages.append(new_message)
                    except dpkt.NeedData:
                        #print '   saving residue'
                        self.plaintext_residue_type = rec.type
                        self.plaintext_residue = plaintext[pointer:]
                        break
            self.plaintext.extend(new_messages)
            for msg in new_messages:
                #print '   sending message to period'
                self.period.process_message(self, msg)
            return new_messages
        else:
            # no new records, no new messages
            return []

    def clear_encrypted(self):
        '''Get rid of encrypted TLS records.'''
        self.encrypted.clear()
        self.encrypted = None


class Period(object):
    '''
    Packets that passed during a connection state's duration, and information
    derived therefrom.

    Picks up stuff like the handshake and associated parameters for
    next connection state (if any), and at some point decrypts and decompresses
    its TLSRecord's with the help of Plex's derived from its own Params.
    Finishes when both Plex's have received ChangeCipherSpec.

    * fwd: Plex, handles decrypting forward stream.
    * rev: Plex that handles reverse stream.
    * to_server: ref to either fwd or rev, depending on which one
        contains packets sent to the server, or None if not known yet.
    * params: Params. Must be passed in complete.
    * server_hello: TLSHandshake, the ServerHello for any handshake happening
        during this state.
    * client_hello: TLSHandshake, the ClientHello.
    '''

    def __init__(self, prev_period, tls_session_manager):
        '''
        Get ready to receive and process packets.

        Args:
        * prev_period: Period from which we'll grab all the parameters
            we need, or None if no previous period
        * tls_session_manager: session.SessionManager or None
        '''
        # figure out params from prev_period. This is mainly cipher_suite and
        # compression. This code also needs to set fwd_is_server for the
        # creation of plexes below.
        #print 'creating Period'
        if prev_period is None:
            #print '  no previous period'
            self.params = Params(None, dpkt.ssl_ciphersuites.BY_CODE[0x00])
            fwd_is_server = True  # just guessing, it doesn't matter now anyway.
            #print 'Creating ConnStatePeriod from nothing'
        else:
            if prev_period.server_hello:
                cipher_suite = prev_period.server_hello.data.cipher_suite
                #print '  grabbed cipher_suite', `cipher_suite`
                compression = prev_period.server_hello.data.compression
                #print 'Creating ConnStatePeriod cs %s comp %d' % (
                #    cipher_suite.name, compression)
                server_random = prev_period.server_hello.data.random
            else:
                # no server hello in a previous period is pretty weird. This
                # should never happen.
                #print '  no server_hello in prev_period'
                cipher_suite = dpkt.ssl_ciphersuites.BY_CODE[0x00]
                compression = 0x00
                server_random = None
            master_secret = None
            client_random = None
            if prev_period.client_hello:
                client_random = prev_period.client_hello.data.random
                if tls_session_manager:
                    # this might just return None anyway.
                    master_secret = tls_session_manager.get_master_secret(
                        client_random)
                    if not master_secret:
                        print 'woops, no secret for %r' % client_random
                    else:
                        print 'yes, got it'
            self.params = Params(None, cipher_suite,
                                 compression=compression,
                                 client_random=client_random,
                                 server_random=server_random,
                                 master_secret=master_secret,)
            # figure out fwd_is_server
            if prev_period.to_server is prev_period.fwd:
                #print '  fwd_is_server = True'
                fwd_is_server = True
            else:
                #print '  fwd_is_server = False'
                fwd_is_server = False
        # create plexes
        self.fwd = Plex(self, self.params, not fwd_is_server)
        self.rev = Plex(self, self.params, fwd_is_server)
        self.to_server = self.fwd if fwd_is_server else self.rev
        # set misc vars for benefit of next period
        self.server_hello = self.client_hello = None

    def process_message(self, plex, message):
        '''
        Do non-plex-specific processing of message, mainly handshake detection.

        Args:
        * plex: Plex sending on which the message arrived
        '''
        assert plex in (self.fwd, self.rev)
        other_plex = self.fwd if plex is self.rev else self.rev
        if isinstance(message, dpkt.ssl.TLSHandshake):
            #print 'processing Handshake'
            # the server READS ClientHello's, and vice versa
            if isinstance(message.data, dpkt.ssl.TLSClientHello):
                print '  ClientHello'
                plex.client_perspective = False
                other_plex.client_perspective = True
                self.to_server = plex  # read by server
                self.client_hello = message
            elif isinstance(message.data, dpkt.ssl.TLSServerHello):
                print '  ServerHello'
                plex.client_perspective = True
                other_plex.client_perspective = False
                self.to_server = other_plex
                self.server_hello = message
        else:
            pass
            #print 'processing non-Handshake', repr(message)
