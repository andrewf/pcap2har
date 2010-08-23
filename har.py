'''
Parses a list of HTTPFlows into data suitable for writing to a HAR file.
'''

class Page:
    def __init__(self, title, startedDateTime):
        self.title = title
        self.startedDateTime = startedDateTime

class Entry:
    def __init__(self, request, response):
        self.request = request
        self.response = response
        self.total_time = (response.end_time - request.start_time) + startup_time

def extract_data(httpdata):
    '''
    Extracts http data from the httpdata and converts it into a python dict
    suitable for writing straight out as a HAR.

    Args:
    httpflows = [http.MessagePair]

    Returns:
    {} = HAR data
    '''
