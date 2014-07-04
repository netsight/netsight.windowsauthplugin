# -*- coding: utf-8 -*-
"""
This module contains the tool of netsight.windowsauthplugin
"""
import os
from setuptools import setup, find_packages


def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

version = '2.3.1'

long_description = (
    read('README.rst')
    + '\n' +
    'Change history\n'
    '**************\n'
    + '\n' +
    read('docs', 'CHANGES.txt')
    + '\n' +
    'Contributors\n'
    '************\n'
    + '\n' +
    read('docs', 'CONTRIBUTORS.txt')
    + '\n' +
    'Download\n'
    '********\n')

tests_require = ['zope.testing']

setup(name='netsight.windowsauthplugin',
      version=version,
      description="A Windows Integrated Authentication (SPNEGO/Kerberos) Plugin for PAS",
      long_description=long_description,
      # Get more strings from
      # http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        'Framework :: Plone',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        ],
      keywords='',
      author='Matt Hamilton',
      author_email='matth@netsight.co.uk',
      url='https://github.com/netsight/netsight.windowsauthplugin',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['netsight'],
      include_package_data=True,
      zip_safe=False,
      install_requires=['setuptools',
                        # -*- Extra requirements: -*-
                        ],
      tests_require=tests_require,
      extras_require=dict(tests=tests_require,
                          win32=[],
                          unix=['kerberos',]),
      test_suite='netsight.windowsauthplugin.tests.test_docs.test_suite',
      entry_points="""
      # -*- entry_points -*-

      [z3c.autoinclude.plugin]
      target = plone
      """,
      )
