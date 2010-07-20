import dpkt


def friendly_tcp_flags(flags):
    '''returns a string containing a user-friendly representation of the tcp flags'''
    d = {dpkt.tcp.TH_FIN:'FIN', dpkt.tcp.TH_SYN:'SYN', dpkt.tcp.TH_RST:'RST', dpkt.tcp.TH_PUSH:'PUSH', dpkt.tcp.TH_ACK:'ACK', dpkt.tcp.TH_URG:'URG', dpkt.tcp.TH_ECE:'ECE', dpkt.tcp.TH_CWR:'CWR'}
    #make a list of the flags that are activated
    active_flags = filter(lambda t: t[0] & flags, d.iteritems()) #iteritems (sortof) returns a list of tuples
    #join all their string representations with '|'
    return '|'.join(t[1] for t in active_flags)

def friendly_socket(sock):
    '''returns a socket where the addresses are converted by inet_ntoa. sock
    is in tuple format, like ((sip, sport),(dip, sport))'''
    return '((%s, %d), (%s, %d))' % (
        inet_ntoa(sock[0][0]),
        sock[0][1],
        inet_ntoa(sock[1][0]),
        sock[1][1]
    )

