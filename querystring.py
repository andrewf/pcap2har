pair_separator = '&'

class QueryStringParser:
    def __init__(self, string):
        self.values= {}
        pairs = string.split(pair_separator)
        for pair in pairs:
            if pair == '': continue
            n, v = pair.split('=')
            self.values[n] = v

if __name__ == '__main__':
    for s in ['', 'f=345&SOMETHING=something+else', 'SDK=FOO&page=32n84923n93409j3']:
        q = QueryStringParser(s)
        pass