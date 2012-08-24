'''
A flow using SSL or TLS encryption
'''
import logging
from .direction import Direction

class Flow(object):
    '''
    Encrypted data flow.

    Takes a tcp.Flow and wraps it in a compatible interface that
    exposes the decrypted data.

    Members:
    * fwd: ssl.Direction
    * rev: ssl.Direction
    * tcpflow: tcp.Flow
    '''

    # should be constructible with tcp.Flow with packets, for
    # after-the-fact decryption?
    def __init__(self, tcpflow):
        self.tcpflow = tcpflow
        self.fwd = Direction(self, tcpflow.fwd)
        self.rev = Direction(self, tcpflow.rev)

    def add(self, pkt):
        self.tcpflow.add(pkt) # also updates the tcpdirs owned by self.fwd/rev
        logging.info('https packet')

    def finish(self):
        self.tcpflow.finish()
