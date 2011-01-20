class Page(object):
    '''
    Members:
    * pageref
    * url
    * startedDateTime
    * title = url
    '''
    def __init__(self, pageref, entry):
        '''
        Creates new page with passed ref and data from entry
        '''
        self.pageref = pageref
        self.url = entry.request.url
        self.startedDateTime = entry.startedDateTime
        self.title= self.url
    def json_repr(self):
        return {
            'id': self.pageref,
            'startedDateTime': self.startedDateTime.isoformat() + 'Z',
            'title': self.title,
            'pageTimings': default_page_timings
        }


default_page_timings = {
    'onContentLoad': -1,
    'onLoad': -1
}

class PageTracker(object):
    '''
    Groups http entries into pages.

    Takes a series of http entries and returns string pagerefs. Divides them
    into pages based on http referer headers (and maybe someday by temporal
    locality). Basically all it has to do is sort entries into buckets by any
    means available.
    '''
    def __init__(self):
        self.page_number = 0 # used for generating pageids
        self.pages = {} # {referer_url: Page}
    def getref(self, entry):
        '''
        takes an Entry and returns a pageref.

        Entries must be passed in by order of arrival
        '''
        req = entry.request # all the interesting stuff is in the request
        if 'referer' in req.msg.headers:
            referer = req.msg.headers['referer']
            if referer in self.pages:
                return self.pages[referer].pageref
            else:
                # make new page for this entry; assume referer is
                self.pages[referer] = Page(self.new_id(), entry)
                return self.pages[referer].pageref
        else:
            # make a new page; supposedly other entries will refer to it
            self.pages[entry.request.url] = Page(self.new_id(), entry)
            return self.pages[entry.request.url].pageref
    def new_id(self):
        result = 'page_%d' % self.page_number
        self.page_number += 1
        return result
    def json_repr(self):
        return sorted(self.pages.itervalues())