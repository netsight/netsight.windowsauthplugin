from zope.interface import Interface
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, \
    ILoginPasswordExtractionPlugin, \
    IChallengePlugin

class IWindowsauthpluginHelper( IAuthenticationPlugin,
                                ILoginPasswordExtractionPlugin,
                                IChallengePlugin,
                                ):
    """interface for WindowsauthpluginHelper."""


class IWindowsAuthPluginMixedLayer(Interface):
    """"Marker interface that defines a ZTK browser layer."""
