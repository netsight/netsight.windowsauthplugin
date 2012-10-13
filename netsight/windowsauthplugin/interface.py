from Products.PluggableAuthService.interfaces.plugins import *
from Products.PlonePAS.interfaces.group import IGroupIntrospection

class IWindowsauthpluginHelper( IAuthenticationPlugin,
                                ILoginPasswordExtractionPlugin,
                                IChallengePlugin,
                                IUserEnumerationPlugin,
                                IPropertiesPlugin,
                                IGroupsPlugin,
                                IGroupEnumerationPlugin,
                                IGroupIntrospection,
                                ):
    """interface for WindowsauthpluginHelper."""
