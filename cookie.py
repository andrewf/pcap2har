
class CookieError(Exception):
    pass

def parse_attrs(data):
    '''
    Parses attributes in a cookie string. Returns dictionary.
    '''
    attrs = data.split(';')
    d = {}
    def parse_av_pair(pair):
        '''
        parses a string in the form ' name   = value ' into ('name', 'value')
        '''
        pair = pair.split('=')
        if len(pair) == 2:
            n, v = pair
        else:
            raise CookieError('wrong number of items in alleged pair', pair)
        return n.strip(), v.strip()
    # go through attrs (ignore requirement that 'name' is first)
    for attr in attrs:
        n, v = parse_av_pair(attr)
        d[n] = v
    return d


class Cookie(object):
    '''
    Represents a cookie transmitted through HTTP. Parses the data out of a
    string, including the name. Directly JSON-serializable.
    '''
    def __init__(self, data):
        d = parse_attrs(data)
        self.name = 'foo'

    def json_repr(self):
        d = {
            'name': self.name,
            'value': self.value,
        }
        if self.path:
            d['path'] = self.path
        if self.domain:
            d['domain'] = self.domain
        if self.expires:
            d['expires'] = self.expires
        if self.httpOnly:
            d['httpOnly'] = self.httpOnly

if __name__ == '__main__':
    strings = [
        '__utma=191645736.1924309581.1277516327.1278893750.1278979018.10; __utmz=191645736.1278979018.10.3.utmcsr=wiki.wireshark.org|utmccn=(referral)|utmcmd=referral|utmcct=/Development/LibpcapFileFormat; __qca=P0-1746884488-127751374326',
    ]
    for s in strings:
        c = Cookie(s)