# Copyright 2012 Google Inc. All Rights Reserved.

'''
Manage and retrieve TLS sessions.
'''


import binascii


class SessionManager(object):
    '''
    Provide mapping from sessions/client_randoms to master_secrets.

    Optionally takes a keylog filename, and uses it to create a mapping from
    client_random values to master_secret's. Later it will do more complicated
    stuff to keep track of session IDs and stuff.
    '''

    def __init__(self, keylog=None):
        '''
        Basically, load a keylog file if one is supplied

        Args:
        * keylog: file-like object containing keylog data.
        '''
        self.random_to_master = {}
        if keylog is not None:
            self.load_keylog(keylog)

    def load_keylog(self, keylog):
        '''
        Parse the passed keylog file into self.random_to_master.  Ignore
        RSA entries for now.

        Args:
        * keylog: file-like object containing keylog data.
        '''
        for no, line in enumerate(keylog.readlines()):
            if line[0] == '#':
                continue
            items = line.split()
            if len(items) != 3:
                logging.warning('Line %d of the keylog is invalid.')
                continue
            if items[0] == 'CLIENT_RANDOM':
                try:
                    self.random_to_master[binascii.a2b_hex(items[1])] = (
                          binascii.a2b_hex(items[2]))
                except TypeError:
                    # probably raised by binascii
                    continue
            else:
                logging.warning('Keylog entry of type %s is unsupported.' %
                                items[0])

    def get_master_secret(self, client_random):
        '''
        Use client_random to get the master_secret for that session.
        '''
        return self.random_to_master.get(client_random)
