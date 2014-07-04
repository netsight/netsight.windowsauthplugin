from Products.CMFCore.utils import getToolByName
from Products.Five import BrowserView

REDIRECT_JS = u"""\
(function() {
    /* http://stackoverflow.com/questions/901115/ */
    function getParameterByName(name) {
        name = name.replace(/[\[]/, '\\\[').replace(/[\]]/, '\\\]');
        var regex = new RegExp('[\\?&]' + name + '=([^&#]*)'),
        results = regex.exec(location.search);
        return results == null ? '' :
               decodeURIComponent(results[1].replace(/\+/g, ' '));
    }
    /* Redirect authenticated user to 'logged_in', retaining came_from */
    var came_from = getParameterByName('came_from');
    window.location.replace('%s/logged_in?came_from=' + came_from);
})();
"""


class SPNEGOChallengeJSView(BrowserView):

    def __call__(self):
        """Challenge the user for credentials before returning javascript.
        """
        response = self.request.response

        # Set no-cache headers
        response.setHeader('Cache-Control',
                           'no-cache, no-store, must-revalidate')
        response.setHeader('Pragma', 'no-cache')
        response.setHeader('Expires', '0')

        # Select response
        mtool = getToolByName(self.context, 'portal_membership')
        if mtool.isAnonymousUser():
            response.addHeader('WWW-Authenticate', 'Negotiate')
            response.addHeader('Connection', 'keep-alive')
            response.addHeader('Content-Type', 'text/javascript')
            response.setStatus(401)
            return u"/* You are not authorized to access this resource. */"
        elif not bool(self.request.response.cookies):
            return u"/* Authentication cookie was not set. Cannot redirect. */"
        else:
            # Return Javascript to redirect and continue login process
            return REDIRECT_JS % self.context.portal_url()
