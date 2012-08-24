# Copyright 2012 Google Inc. All Rights Reserved.

'''
Manage and retrieve TLS sessions.
'''

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
        pass

    def get_master_secret(self, client_random):
        '''
        Use client_random to get the master_secret for that session.
        '''
        return self.random_to_master.get(client_random)
