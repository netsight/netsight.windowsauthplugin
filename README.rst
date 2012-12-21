Introduction
============

netsight.windowsauthplugin is a Plone authentication plugin to do
Single Sign On (SSO) in a Windows Active Directory environment.

It uses the same underlying authentication mechanisms as Windows uses
internally, known as Integrated Windows Authentication. This uses
Kerberos underneath to do the actual authentication.


Glossary
========

`Integrated Windows Authentication (IWA) <http://en.wikipedia.org/wiki/Integrated_Windows_Authentication>`_
  This is Microsoft's is a term associated with Microsoft products
  that refers to the SPNEGO, Kerberos, and NTLMSSP authentication
  protocols with respect to SSPI functionality introduced with
  Microsoft Windows 2000 and included with later Windows NT-based
  operating systems. The term is used more commonly for the
  automatically authenticated connections between Microsoft Internet
  Information Services, Internet Explorer, and other Active Directory
  aware applications.

`Kerberos <http://en.wikipedia.org/wiki/Kerberos_(protocol)>`_
  Kerberos is a network authentication protocol. It is designed to
  provide strong authentication for client/server applications by
  using secret-key cryptography. It is a standardised protocol and
  used by Unix, Linux, Windows and Mac OSX for authentication services.

