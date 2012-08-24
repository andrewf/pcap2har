

class Direction(object):
    '''
    One side of an SSL flow

    Members:
    * tcpdir: tcp.Direction
    '''
    def __init__(self, flow, tcpdir):
        '''
        Args:
        * flow: ssl.Flow this belongs to
        * tcpdir: tcp.Direction that this obj will work with
        '''
        self.flow = flow
        self.tcpdir = tcpdir

    #def add?(self):
    #    # but this is handled by tcp.Flow called by ssl.Flow
    #    pass

    @property
    def data(self):
        return self.tcpdir.data

    def byte_to_seq(self, byte):
        # this fn may be replaced by byte_final_arrival
        pass

    def seq_final_arrival(self, seq):
        # this fn may be replaced by byte_final_arrival
        pass
