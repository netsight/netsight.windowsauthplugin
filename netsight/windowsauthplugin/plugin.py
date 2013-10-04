"""Class: WindowsauthpluginHelper
"""

from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

from zExceptions import Forbidden
from zLOG import LOG, ERROR, DEBUG, INFO

import sys

if sys.platform == 'win32':
    WINDOWS = 1
else:
    WINDOWS = 0

if WINDOWS:
    import sspi, sspicon
else:
    import kerberos
    from kerberos import GSSError

import interface

class WindowsauthpluginHelper( BasePlugin ):
    """Multi-plugin to do Kerberos based SSO

    """

    meta_type = 'SPNEGO Kerberos Plugin'
    security = ClassSecurityInfo()

    removerealm = 1
    removedomain = 1
    autogroups = ['Member',]

    _properties = (
            {
                 "id": "autogroups",
                 "label": "Additional Groups to add to this user",
                 "type": "lines",
                 "mode": "w",
             },
            {
                 "id": "removerealm",
                 "label": "Remove realm from username",
                 "type": "boolean",
                 "mode": "w",
             },
            {
                 "id": "removedomain",
                 "label": "Remove domain from username",
                 "type": "boolean",
                 "mode": "w",
             },

    )

    def __init__( self, id, title=None ):
        self._setId(id)
        self.title = title
        self.auth_scheme = 'Negotiate'
        self.service = 'HTTP'

    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials ):

        """ See IAuthenticationPlugin.

        o We expect the credentials to be those returned by
          ILoginPasswordExtractionPlugin.
        """
        # We only authenticate when our challenge mechanism extracted
        # the ticket
        if credentials.get('plugin') != self.getId():
            return None

        request = self.REQUEST
        response = request.RESPONSE
        remote_host = request.getClientAddr()

        # We are actually already authenticated... maybe we are in a subrequest
        if request.get('AUTHENTICATED_USER', None) is not None:
            username = request.AUTHENTICATED_USER.getName()
            return username, username

        ticket = credentials['ticket']

        if WINDOWS:
            sa = sspi.ServerAuth('Negotiate')
            sa.reset()
            data = ticket.decode('base64')
            err, sec_buffer = sa.authorize(data)
        
            if err == 0:
                username = sa.ctxt.QueryContextAttributes(
                    sspicon.SECPKG_ATTR_NAMES)		               
            else:
                raise Forbidden

        else:
            result, context = kerberos.authGSSServerInit(self.service)
            if result != 1:
                raise ValueError, "Kerberos authetication error"

            gssstring=''
            try:
                r=kerberos.authGSSServerStep(context,ticket)
                if r == 1:
                    gssstring=kerberos.authGSSServerResponse(context)
                else:
                    raise Forbidden
            except GSSError, e:
                LOG('SPNEGO plugin', ERROR,  "%s: GSSError %s" % (remote_host, e))
                raise Forbidden

            username=kerberos.authGSSServerUserName(context)
            kerberos.authGSSServerClean(context)
            
        # strip off the realm and domain
        if self.removerealm and '@' in username:
            username = username.split('@')[0]
        if self.removedomain and '\\' in username:
            username = username.split('\\')[1]

        # Convert to unicode before returning
        username = username.encode('utf-8')

        # Trigger the session plugin
        LOG('SPNEGO plugin', DEBUG,  "%s: Have authenticated user: %s" % (remote_host, username))
        pas_instance = self._getPAS()
        if pas_instance is not None:
            response = request.RESPONSE
            pas_instance.updateCredentials(request, response, username, '')

        return username, username


    security.declarePrivate( 'extractCredentials' )
    def extractCredentials( self, request ):

        """ Extract final auth credentials from 'request'.
        """
        if not request._auth or not request._auth.startswith(self.auth_scheme):
            return None
        
        ticket = request._auth[len(self.auth_scheme)+1:]
        remote_host = request.getClientAddr()

        # Detect if NTLM is used and issue a warning and abort
        if ticket.startswith('TlRM'):
            LOG('SPNEGO plugin', INFO, "%s: Attempted to use unsupported NTLM auth" % (remote_host))
            return

        creds = {}
        creds['ticket'] = ticket
        creds['plugin'] = self.getId()

        return creds
        
    security.declarePrivate( 'challenge' )
    def challenge( self, request, response, **kw ):

        """ Challenge the user for credentials.
        """
        # If browser is coming back with auth, yet we are still challenging
        # that means there is insufficient privs.
        if request._auth and request._auth.startswith(self.auth_scheme):
            return False
        response.addHeader('WWW-Authenticate', self.auth_scheme)
        response.addHeader('Connection', 'keep-alive')
        response.setStatus(401)
        m = "<strong>You are not authorized to access this resource.</strong>"
        response.setBody(m, is_error=1)
        return True


classImplements(WindowsauthpluginHelper, 
                interface.IWindowsauthpluginHelper)

InitializeClass( WindowsauthpluginHelper )
