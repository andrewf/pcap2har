class Message(object):
    '''
    Contains a dpkt.http.Request/Response, as well as other data required to
    build a HAR, including (mostly) start and end time.

    * msg: underlying dpkt class
    * data_consumed: how many bytes of input were consumed
    * seq_start: first sequence number of the Message's data in the tcpdir
    * seq_end: first sequence number past Message's data (slice-style indices)
    * ts_start: when Message started arriving (dpkt timestamp)
    * ts_end: when Message had fully arrived (dpkt timestamp)
    * raw_body: body before compression is taken into account
    * tcpdir: The tcp.Direction corresponding to the HTTP message
    '''

    def __init__(self, tcpdir, pointer, msgclass):
        '''
        Args:
        tcpdir = tcp.Direction
        pointer = position within tcpdir.data to start parsing from. byte index
        msgclass = dpkt.http.Request/Response
        '''
        self.tcpdir = tcpdir
        # attempt to parse as http. let exception fall out to caller
        self.msg = msgclass(tcpdir.data[pointer:])
        self.data_consumed = (len(tcpdir.data) - pointer) - len(self.msg.data)
        # save memory by deleting data attribute; it's useless
        self.msg.data = None
        # calculate arrival_times
        self.ts_start = tcpdir.byte_final_arrival(pointer)
        self.ts_end = tcpdir.byte_final_arrival(pointer + self.data_consumed - 1)
        # get raw body
        self.raw_body = self.msg.body
        self.__pointer = pointer
        # Access self.__raw_msg via raw_msg @property, which will set it if None
        self.__raw_msg = None

    @property
    def raw_msg(self):
        '''
        Returns the message (including header) as a byte string.
        '''
        if not self.__raw_msg:
          self.__raw_msg = self.tcpdir.data[
              self.__pointer:(self.__pointer+self.data_consumed)]
        return self.__raw_msg
