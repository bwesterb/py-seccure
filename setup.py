#!/usr/bin/env python

import sys
from setuptools import setup
from get_git_version import get_git_version

install_requires = [
    'pycrypto >=2.6',        # TODO do we need this version
    'gmpy >=1.15, <2',       #      ibidem
    'six >=1.2',             #      ibidem
        ]

setup(
    name='seccure',
    version=get_git_version(),
    description='SECCURE compatible Elliptic Curve cryptography',
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='http://github.com/bwesterb/py-seccure',
    packages=['seccure', 'seccure.tests'],
    package_dir={'seccure': 'src'},
    license='LGPL 3.0',
    install_requires=install_requires,
    classifiers = [
            'Development Status :: 3 - Alpha',
            'License :: OSI Approved ::' +
                ' GNU Lesser General Public License v3 (LGPLv3)',
            'Operating System :: POSIX',
            'Topic :: Security',
            'Programming Language :: Python :: 2.6',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.2',
            'Programming Language :: Python :: 3.3',
        ],
    test_suite='seccure.tests',
    ),
