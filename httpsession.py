'''
Parses a list of HTTPFlows into data suitable for writing to a HAR file.
'''

from datetime import datetime
from pcaputil import ms_from_timedelta, ms_from_dpkt_time

class Page:
    def __init__(self, title, startedDateTime):
        self.title = title
        self.startedDateTime = startedDateTime # python datetime

class Entry:
    '''
    represents an HTTP request/response in a form suitable for writing to a HAR
    file.
    Members:
    * request = http.Request
    * response = http.Response
    * page_ref = string
    * startedDateTime = python datetime
    * total_time = from sending of request to end of response, milliseconds
    * time_blocked
    * time_dnsing
    * time_connecting
    * time_sending
    * time_waiting
    * time_receiving
    '''
    def __init__(self, request, response):
        self.request = request
        self.response = response
        self.page_ref = ''
        self.startedDateTime = datetime.fromtimestamp(request.ts_start)
        endedDateTime = datetime.fromtimestamp(response.ts_end)
        self.total_time = ms_from_timedelta(
            endedDateTime - self.startedDateTime # plus connection time, someday
        )
        # calculate other timings
        self.time_blocked = -1
        self.time_dnsing = -1
        self.time_connecting = -1
        self.time_sending = \
            ms_from_dpkt_time(request.ts_end - request.ts_start)
        self.time_waiting = \
            ms_from_dpkt_time(response.ts_start - request.ts_end)
        self.time_receiving = \
            ms_from_dpkt_time(response.ts_end - response.ts_start)
        # check if timing calculations are consistent
        if self.time_sending + self.time_waiting + self.time_receiving != self.total_time:
            pass
    def json_repr(self):
        '''
        return a JSON serializable python object representation of self.
        '''
        return {
            'page_ref': self.page_ref,
            'startedDateTime': self.startedDateTime.isoformat(),
            'time': self.total_time,
            'request': self.request,
            'response': self.response,
            'timings': {
                'blocked': self.time_blocked,
                'dns': self.time_dnsing,
                'connect': self.time_connecting,
                'send': self.time_sending,
                'wait': self.time_waiting,
                'receive': self.time_receiving
            }
        }

class UserAgentTracker:
    def __init__(self):
        self.data = {} # {user-agent string: number of uses}
    def add(self, string):
        '''
        either increments the use-count, or creates a new entry
        '''
        if string in self.data:
            self.data[string] += 1
        else:
            self.data[string] = 1
    def dominant_user_agent(self):
        '''
        The agent string with the most uses
        '''
        if not len(self.data):
            return None
        elif len(self.data) == 1:
            return self.data.keys()[0]
        else:
            # max returns first value of tuple produced when iterating through
            # dict, in this case, the user-agent string, even though the key
            # function has access to the full tuple
            return max(self.data, key=lambda v: v[0])

class HTTPSession(object):
    '''
    Represents all http traffic from within a pcap.
    
    Members:
    * user_agent = most-used user-agent in the flow
    * referers = referers/page-loads
    '''
    def __init__(self, messages):
        '''
        Parses http.MessagePairs to get http info out, in preparation for
        writing it to a HAR file.
        '''
        # set-up
        self.user_agents = UserAgentTracker()
        self.entries = []
        # iter through messages
        for msg in messages:
            # if msg.request has a user-agent, add it to our list
            if 'user-agent' in msg.request.msg.headers:
                self.user_agents.add(msg.request.msg.headers['user-agent'])
            # if msg.request has a referer, keep track of that, too
            if 'referer' in msg.request.msg.headers:
                # not really
                pass
            # parse basic data in the pair, add it to the list
            self.entries.append(Entry(msg.request, msg.response))
        # finish calculating data
        self.user_agent = self.user_agents.dominant_user_agent()    
    def json_repr(self):
        '''
        return a JSON serializable python object representation of self.
        '''
        return {
            'log': {
                'version' : '1.1',
                'creator': {
                    'name': 'pcap2har',
                    'version': '0.1'
                },
                'browser': {
                    'name': self.user_agent,
                    'version': 'mumble'
                },
                'pages': [],
                'entries': self.entries
            }
        }
