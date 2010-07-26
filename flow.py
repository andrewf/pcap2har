from socket import inet_ntoa


class Flow(object):
    def __init__(self, socket, index, packets):

        # Save params
        self.socket = socket
        self.index = index
        self.orig_index = index
        self.packets = packets

        # Unpack socket
        s, d = socket
        sip, self.sport = s
        dip, self.dport = d
        self.sip = inet_ntoa(sip)
        self.dip = inet_ntoa(dip)
        self.hostname = '('+self.dip+')'

        # Time analysis
        self.start = min(p.ts for p in self.packets)
        self.end = max(p.ts for p in self.packets)
        self.duration = self.end - self.start

        self.analyze()

    @property
    def real_flow(self):
        return self

    def analyze(self):
        """
        Subclasses should override this to do post __init__()
        processing without having to override __init__().
        """
        pass

    def __repr__(self):
        return '%s <%s, start=%s>' % (
            self.__class__.__name__,
            flow_str(self.socket),
            self.start
        )
    def __cmp__(self, other):
        """Flows are compared based on their start time."""
        return cmp(self.start, other.start)
    def __eq__(self, other):
        return not self.__ne__(other)
    def __ne__(self, other):
        if isinstance(other, Flow):
            return self.__cmp__(other) != 0
        else:
            return True

