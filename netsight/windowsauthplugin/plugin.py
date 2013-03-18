"""Class: WindowsauthpluginHelper
"""

from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.UserPropertySheet import UserPropertySheet

from Products.PlonePAS.plugins.group import PloneGroup
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin

from zExceptions import Unauthorized, Forbidden
from zLOG import LOG, INFO, ERROR, DEBUG

import sys
import re
from time import time
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
import ldap

from plone.memoize import ram

class WindowsauthpluginHelper( BasePlugin ):
    """Multi-plugin

    """

    meta_type = 'SPNEGO Kerberos Plugin'
    security = ClassSecurityInfo()

    removerealm = 1
    removedomain = 1
    ldapurl = ''
    ldapbinddn = ''
    ldapbindpw = ''
    ldapsearchbase = ''
    ldapgroupsearchbase = ''
    ldapsearchscope = 'ONELEVEL'
    ldapgroups = 1
    autogroups = ['Member',]

    _properties = (
            {
                 "id": "ldapurl",
                 "label": "Domain Controller LDAP URL",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "ldapbinddn",
                 "label": "Domain Controller LDAP Bind DN",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "ldapbindpw",
                 "label": "Domain Controller LDAP Bind Password",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "ldapsearchbase",
                 "label": "Domain Controller LDAP User search base",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "ldapgroupsearchbase",
                 "label": "Domain Controller LDAP Group search base",
                 "type": "string",
                 "mode": "w",
             },
            {
                 "id": "ldapsearchscope",
                 "label": "LDAP Search Scope",
                 "type": "string",
                 "mode": "w",
             },

            {
                 "id": "ldapgroups",
                 "label": "Get groups from AD",
                 "type": "boolean",
                 "mode": "w",
             },
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

        # Can't remember why we do this anymore, but probably to trigger the session plugin
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

    #
    #   IUserEnumerationPlugin implementation
    #
    security.declarePrivate('enumerateUsers')
    @ram.cache(lambda *args, **kwargs: (time() // (60 * 60), args, kwargs))
    def enumerateUsers(self, id=None
                       , login=None
                       , exact_match=False
                       , sort_by=None
                       , max_results=None
                       , **kw
                       ):
        """ See IUserEnumerationPlugin.
        """
        key = id or login
        fullname = kw.get('fullname')

        if key:
            if exact_match:
                query = '(&(objectCategory=person)(|(objectClass=contact)(objectClass=user))(sAMAccountName=%s))' % key
            else:
                query = '(&(objectCategory=person)(|(objectClass=contact)(objectClass=user))(sAMAccountName=*%s*))' % key

        if fullname:
            if exact_match:
                query = '(&(objectCategory=person)(|(objectClass=contact)(objectClass=user))(displayName=%s))' % fullname
            else:
                query = '(&(objectCategory=person)(|(objectClass=contact)(objectClass=user))(displayName=*%s*))' % fullname

        res = self.doQuery(query, ['sAMAccountName'])

        res = [ r for r in res if r[0] ]
        userids = [ r[1].get('sAMAccountName') for r in res ]
        userids = [ r[0] for r in userids if r ]
        if max_results:
            userids = userids[:max_results]
        return [ {'id': id, 'login': id, 'pluginid': self.getId()} for id in userids ]

    def doQuery(self, query, attrs=None):
        LOG('SPNEGO plugin', DEBUG, 'LDAP Query: %s' % query)
        conn = ldap.initialize(self.ldapurl)
        conn.set_option(ldap.OPT_REFERRALS,0)
        conn.simple_bind_s(self.ldapbinddn, self.ldapbindpw)
        res = conn.search_s(self.ldapsearchbase,
                            getattr(ldap, 'SCOPE_%s' % self.ldapsearchscope),
                            query,
                            attrs,
                            )
        return res

    @ram.cache(lambda *args, **kwargs: (time() // (60 * 60), str(args[2]), kwargs))
    def getPropertiesForUser(self, user, request=None):

        # we don't bother looking in AD for groups
#        try:
#            if user.isGroup():
#                return
#        except AttributeError:
#            return

        user = str(user)

        res = self.doQuery('(&(objectCategory=person)(|(objectClass=contact)(objectClass=user))(sAMAccountName=%s))' % user,
                           ['displayName', 'sAMAccountName', 'mail', 'memberOf'])

        if len(res) > 0: # we found them
            try:
                email = res[0][1]['mail'][0]
            except KeyError:
                email = ''
            except TypeError:
                return None
            try:
                fullname = res[0][1]['displayName'][0]
            except KeyError:
                fullname = ''
            if not fullname:
                fullname = user
            try:
                groups = res[0][1]['memberOf']
                def extractgroup(group):
                    try:
                        return re.search('cn=([^,]+)', group, re.I).group(1)
                    except AttributeError:
                        return None
                groups = [ extractgroup(g) for g in groups ]
                groups = [ g for g in groups if g]
            except KeyError:
                groups = []

            return UserPropertySheet(user, fullname=fullname, email=email, groups=groups, domain='AD')
    
    @ram.cache(lambda *args: (time() // (60 * 60), str(args[2])))
    def getGroupsForPrincipal(self, principal, request=None ):

        """ principal -> ( group_1, ... group_N )

        o Return a sequence of group names to which the principal 
          (either a user or another group) belongs.

        """
        props = self.getPropertiesForUser(principal)
        if props is not None:
            groups = tuple(self.autogroups)
            if self.ldapgroups:
                groups = groups + tuple(props.getProperty('groups'))
            
            LOG('SPNEGO plugin', DEBUG,  'Groups found for user: %s are: %s' % (principal, ', '.join(groups)))
            return groups
        else:
            LOG('SPNEGO plugin', DEBUG,  'No groups found for user: %s' % principal)
            return []

    def enumerateGroups(self, id=None, exact_match=False, sort_by=None, max_results=None, **kw):

        title = kw.get('title')

        if id:
            if exact_match:
                query = '(&(|(objectClass=group)(objectClass=organizationalUnit))(sAMAccountName=%s))' % id
            else:
                query = '(&(|(objectClass=group)(objectClass=organizationalUnit))(sAMAccountName=*%s*))' % id

        elif title:
            if exact_match:
                query = '(&(|(objectClass=group)(objectClass=organizationalUnit))(sAMAccountName=%s))' % title
            else:
                query = '(&(|(objectClass=group)(objectClass=organizationalUnit))(sAMAccountName=*%s*))' % title

        res = self.doQuery(query, ['sAMAccountName'])

        res = [ r for r in res if r[0] ]
        userids = [ r[1].get('sAMAccountName') for r in res ]
        userids = [ r[0] for r in userids if r ]
        if max_results:
            userids = userids[:max_results]
        return [ {'id': id, 'groupid': id, 'pluginid': self.getId()} for id in userids ]

    ### IGroupsIntrospection

    def getGroupById(self, groupid, default=None):

        group = PloneGroup(groupid)
        group = group.__of__(self)
        
        # add UserPropertySheet with title
        # We assume the title is the same as the id
        data = {'title': groupid}
        group.addPropertysheet(self.getId(), data)

        return group

    def getGroups(self):
        return [ self.getGroupById(id) for id in self.getGroupIds() ]

    def getGroupIds(self):
        return [ e['id'] for e in  self.enumerateGroups() ]

    def getGroupMembers(self, groupid):
        query = '(&(objectCategory=person)(|(objectClass=contact)(objectClass=user))(memberOf=cn=%s,*))' % groupid
        res = self.doQuery(query, ['sAMAccountName'])
        
        res = [ r for r in res if r[0] ]
        userids = [ r[1].get('sAMAccountName') for r in res ]
        userids = [ r[0] for r in userids if r ]
        return userids

classImplements(WindowsauthpluginHelper, 
                interface.IWindowsauthpluginHelper)

InitializeClass( WindowsauthpluginHelper )
