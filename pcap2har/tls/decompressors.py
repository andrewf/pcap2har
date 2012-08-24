# Copyright 2012 Google Inc. All Rights Reserved.

'''
Decompressor objects for TLS

Each has a decompress method that returns the data decompressed, updates
state blah blah.

The new(...) function takes an algorithm name and returns a decompressor,
NullDecompressor if the name wasn't found.
'''


class NullDecompressor(object):
    def decompress(self, chunk):
        return chunk


ALGORITHMS = {
    'NULL': NullDecompressor,
}

def new(name, *args, **kwargs):
    return ALGORITHMS.get(name, NullDecompressor)(*args, **kwargs)
