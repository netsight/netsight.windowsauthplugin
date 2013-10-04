from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, \
    ILoginPasswordExtractionPlugin, \
    IChallengePlugin

class IWindowsauthpluginHelper( IAuthenticationPlugin,
                                ILoginPasswordExtractionPlugin,
                                IChallengePlugin,
                                ):
    """interface for WindowsauthpluginHelper."""
