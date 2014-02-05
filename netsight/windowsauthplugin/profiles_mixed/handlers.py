from Products.CMFCore.utils import getToolByName
from Products.PlonePAS.Extensions.Install import activatePluginInterfaces


def configureWindowsAuthPlugin(context):

    marker = 'netsight.windowsauthplugin.profiles_mixed.marker'
    if context.readDataFile(marker) is None:
        return

    site = context.getSite()
    pas = getToolByName(site, 'acl_users')

    if "spnego_auth" not in pas.objectIds():
        factory = pas.manage_addProduct["netsight.windowsauthplugin"]
        factory.manage_add_windowsauthplugin_helper(
            "spnego_auth",
            "Windows authentication plugin"
        )

    # Activate all but Challenge-plugin in mixed environments:
    activatePluginInterfaces(site, "spnego_auth",
                             disable=['IChallengePlugin'])
