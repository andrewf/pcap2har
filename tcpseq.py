
def tcp_seq_subtraction(a, b):
    '''Calculate the difference between a and b, two python integers,
    in a manner suitable for comparing two TCP sequence numbers in a
    wrap-around-sensitive way.'''
    