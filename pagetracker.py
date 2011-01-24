class Page(object):
    '''
    Members:
    * pageref
    * url
    * startedDateTime
    * title = url
    * child_urls = set([string]), urls that have referred to this page, directly
      or indirectly. If anything refers to them, they also belong on this page
    '''
    def __init__(self, pageref, entry):
        '''
        Creates new page with passed ref and data from entry
        '''
        self.pageref = pageref
        self.url = entry.request.url
        self.child_urls = set()
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
            page = self.lookup_referrer(referer)
            # if this request refers to an URL we know about
            if page:
                page.child_urls.add(entry.request.url)
                return page.pageref
            else:
                # make new page for this entry
                return self.new_ref(entry, referer)
        else:
            # make a new page; supposedly other entries will refer to it
            return self.new_ref(entry, entry.request.url)
    def new_ref(self, entry, referrer):
        '''
        Internal. Wraps creating a new pages entry. Returns the new ref
        '''
        if referrer not in self.pages:
            self.pages[referrer] = Page(self.new_id(), entry)
            return self.pages[referrer].pageref
        else:
            raise RuntimeError(
                'tried to get new pageref for existing referrer. Logic error')
    def lookup_referrer(self, referrer):
        '''
        Finds and returns a page that the referrer points to, or returns None
        '''
        if referrer in self.pages:
            return self.pages[referrer]
        # look through the pages, in child_urls and return first match
        for page in self.pages.itervalues():
            if referrer in page.child_urls:
                return page
        # if we got here, we can't find the page
        return None
    def new_id(self):
        result = 'page_%d' % self.page_number
        self.page_number += 1
        return result
    def json_repr(self):
        return sorted(self.pages.itervalues())