from AccessControl.Permissions import manage_users
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService import registerMultiPlugin

import plugin

manage_add_windowsauthplugin_form = PageTemplateFile('browser/add_plugin',
                            globals(), __name__='manage_add_windowsauthplugin_form' )


def manage_add_windowsauthplugin_helper( dispatcher, id, title=None, REQUEST=None ):
    """Add an windowsauthplugin Helper to the PluggableAuthentication Service."""

    sp = plugin.WindowsauthpluginHelper( id, title )
    dispatcher._setObject( sp.getId(), sp )

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'windowsauthpluginHelper+added.'
                                      % dispatcher.absolute_url() )


def register_windowsauthplugin_plugin():
    try:
        registerMultiPlugin(plugin.WindowsauthpluginHelper.meta_type)
    except RuntimeError:
        # make refresh users happy
        pass


def register_windowsauthplugin_plugin_class(context):
    context.registerClass(plugin.WindowsauthpluginHelper,
                          permission = manage_users,
                          constructors = (manage_add_windowsauthplugin_form,
                                          manage_add_windowsauthplugin_helper),
                          visibility = None,
                          icon='browser/icon.gif'
                         )
