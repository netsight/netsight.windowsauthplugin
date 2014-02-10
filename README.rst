Introduction
============

netsight.windowsauthplugin is a Plone authentication plugin to do
Single Sign On (SSO) in a Microsoft Windows Active Directory
environment or other environment that used Kerberos (e.g. Apple MacOS,
or Linux).

It uses the same underlying authentication mechanisms as Windows uses
internally, known as Integrated Windows Authentication. This uses
Kerberos underneath to do the actual authentication.

Current web browsers able to use this plugin to do SSO are Microsoft
Internet Explorer 6+, Mozilla Firefox, Apple Safari, and Google Chrome.

netsight.windowsauthplugin is pure python and can run on Plone on
either a Unix or Windows server. It relies on the MIT
Kerberos libraries (on Unix, Linux, OSX) or the native Windows SSPI
libraries in Windows to so the Kerberos authentication.

Infrastructure Setup
====================

In order for netsight.windowsauthplugin to work you need to have an
Active Directory server (or Kerberos KDC) setup. For this
documentation we will assume:

 - You already have a working AD setup and user accounts.
 - You currently log into a Windows desktop with an AD username/password.
 - You have an admin account or access to a user with an admin account
   on AD and able to create accounts
 - You are using Microsoft Internet Explorer
 - You are running the Plone server on Unix/Linux/OSX

DNS & Time
----------

Kerberos is very particular about DNS and time. Ensure that your
servers and clients are all synced with a network time source. The way
Internet Explorer constructs Kerberos SPNs depends on the host having
a DNS A record. When you try to access a site with IE and are using
Integrated Windows Authentication, IE will attempt to construct a SPN
based upon resolving the hostname to an A record. Hence to avoid
problems, do not use CNAMEs for your DNS records.

Service Principal Names (SPNs) and Keytabs
------------------------------------------

You will need to create a user to associate the SPN with. This can be
a standard user account set to never expire. Ensure that 'Use DES' is
unselected in the properties for the user.

Create the SPNs using the *ktpass* tool as shown below depending on
the version of Windows Server you are using for your Domain
Controller.

The ktpass command below does two things:

 1. Creates the SPN for the service
 2. Exports the keytab to the specified file

In the example below:

 - intranet.example.com is the hostname used in the URL to your site
 - EXAMPLE.COM is your active directory domain
 - plonesvc is the user account created to associate this SPN with
 - c:\\temp\\intranet.keytab is the location of the exported keytab

+----------------+---------------------------------------------------------------------------------------------------+------------------------------------------------+
|                | Windows 2008 SP2 DC                                                                               | Windows 2003 SP3 DC                            |
+----------------+--------------------------------------------------+------------------------------------------------+------------------------------------------------+
| Crypto type    |  RC4                                             | AES256 (not supported by WinXP)                | RC4                                            |
+----------------+--------------------------------------------------+------------------------------------------------+------------------------------------------------+
| ktpass command | | C:\\>ktpass                                    | | C:\\>ktpass                                  | | C:\\>ktpass                                  |
|                | | -princ HTTP/intranet.example.com@EXAMPLE.COM   | | -princ HTTP/intranet.example.com@EXAMPLE.COM | | -princ HTTP/intranet.example.com@EXAMPLE.COM |
|                | | -mapuser plonesvc@EXAMPLE.COM                  | | -mapuser plonesvc@EXAMPLE.COM                | | -mapuser plonesvc@EXAMPLE.COM                |
|                | | -crypto RC4-HMAC-NT                            | | -crypto AES256-SHA1                          | | -crypto rc4-hmac-nt                          |
|                | | -ptype KRB5_NT_PRINCIPAL                       | | -ptype KRB5_NT_PRINCIPAL                     | | -ptype KRB5_NT_SRV_HST                       |
|                | | -pass long!$longp2ass3word                     | | -pass long!$longp2ass3word                   | | -pass longlongpassword                       |
|                | | -out c:\\temp\\intranet.keytab                 | | -out c:\\temp\\intranet.keytab               | | -out c:\\temp\\intranet.keytab               |
+----------------+--------------------------------------------------+------------------------------------------------+------------------------------------------------+

The keytab exported to *c:\\temp\\intranet.keytab* needs to be copied
securely to the server running Plone.

The default path for the keytab file in unix environments is
``/etc/krb5.keytab``, but it can be customized by defining ``KRB5_KTNAME``
environment variable. The keytab must be readable by the user running the Plone
process.

Troubleshooting
===============

- ERROR SPNEGO plugin 127.0.0.1: GSSError (('Unspecified GSS failure. Minor code may provide more information', 851968), ('', 100005))

  **Solution**: This was seen with crypto type AES256 on RHEL6 server.
  This was solved by changing crypto type to RC4.

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
  used by Unix, Linux, Microsoft Windows and Apple Mac OSX for
  authentication services.

`Service Principal Name (SPN) <http://msdn.microsoft.com/en-gb/library/windows/desktop/ms677949(v=vs.85).aspx>`_
  A service principal name (SPN) is the name by which a client
  uniquely identifies an instance of a service. When a client wants to
  connect to a service, it locates an instance of the service,
  composes an SPN for that instance, connects to the service, and
  presents the SPN for the service to authenticate. These often start
  with the service/protocol being used and are then followed by the
  hostname e.g. HTTP/intranet.example.com

`SPNEGO <http://en.wikipedia.org/wiki/SPNEGO>`_
  SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) is a
  GSSAPI "pseudo mechanism" that is used by Microsoft Internet
  Explorer 5.01 and above to negotiate an authentication
  mechanism. The negotiable sub-mechanisms included NTLM and Kerberos,
  both used in Active Directory

`GSSAPI <http://en.wikipedia.org/wiki/Generic_Security_Services_Application_Program_Interface>`_
  GSSAPI (Generic Security Services Application Program Interface) is
  an IETF standard API for accessing a number of authenticatation
  mechanisms. The GSSAPI, by itself, does not provide any
  security. Instead, security service vendors provide GSSAPI
  implementations usually in the form of libraries installed with
  their security software.

`SSPI <http://en.wikipedia.org/wiki/Security_Support_Provider_Interface>`_
  SSPI (Security Support Provider Interface) is an API used by
  Microsoft Windows systems to perform a variety of security-related
  operations such as authentication. SSPI is a proprietary variant of
  GSSAPI with extensions and very Windows-specific data types. For
  Windows 2000, an implementation of Kerberos 5 was added, using token
  formats conforming to the official protocol standard RFC 1964 (The
  Kerberos 5 GSSAPI mechanism) and providing wire-level
  interoperability with Kerberos 5 implementations from other vendors.

`PAS <http://plone.org/documentation/manual/developer-manual/users-and-security/pluggable-authentication-service/>`_
  PAS (Pluggable Authentication Service) is a modular suthantication
  system used by Zope and Plone for the management of users. PAS is
  built around the concepts of interfaces and plugins: all possible
  tasks related to user and group management and authentication are
  described in separate interfaces. These interfaces are implemented
  by plugins, which can be selectively enabled per interface.

`Active Directory <http://en.wikipedia.org/wiki/Active_Directory>`_
  Active Directory (AD) is a directory service created by Microsoft
  for Windows domain networks. It is included in most Windows Server
  operating systems.

  Active Directory provides a central location for network
  administration and security. Server computers that run Active
  Directory are called domain controllers. An AD domain controller
  authenticates and authorizes all users and computers in a Windows
  domain type network—assigning and enforcing security policies for
  all computers and installing or updating software. For example, when
  a user logs into a computer that is part of a Windows domain, Active
  Directory checks the submitted password and determines whether the
  user is a system administrator or normal user.

  Active Directory makes use of Lightweight Directory Access Protocol
  (LDAP) versions 2 and 3, Kerberos and DNS.
