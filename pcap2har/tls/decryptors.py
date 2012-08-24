# Copyright 2012 Google Inc. All Rights Reserved.

'''
Decryptor objects for TLS.

Each has a decrypt(hunk) method that returns the decrypted data
and updates its internal state, if any.

Module also has a new function that takes an algorithm name (and optional
arguments and returns an appropriate decryptor, or NullDecryptor.
'''


class NullDecryptor(object):
    def decrypt(self, hunk):
        return hunk


ALGORITHMS = {
    'NULL': NullDecryptor,
}

def new(name, *args, **kwargs):
    cls = ALGORITHMS.get(name, NullDecryptor)
    return cls(*args, **kwargs)
