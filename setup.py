#!/usr/bin/env python

import os
import sys
import os.path

from setuptools import setup

install_requires = [
    'pycrypto >=2.6',        # TODO do we need this version
    'gmpy >=1.15, <2',       #      ibidem
    'six >=1.2',             #      ibidem
        ]

base_path = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(base_path, 'src', '_version.py')) as f: exec(f.read())

with open(os.path.join(base_path, 'README.rst')) as f, \
     open(os.path.join(base_path, 'CHANGES.rst')) as g:
    long_description = '{0}\n{1}'.format(f.read(), g.read())

setup(
    name='seccure',
    version=__version__,
    description='SECCURE compatible Elliptic Curve cryptography',
    long_description=long_description,
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='http://github.com/bwesterb/py-seccure',
    packages=['seccure', 'seccure.tests'],
    package_dir={'seccure': 'src'},
    license='LGPL 3.0',
    zip_safe=True,
    install_requires=install_requires,
    classifiers = [
            'Development Status :: 4 - Beta',
            'License :: OSI Approved ::' +
                ' GNU Lesser General Public License v3 (LGPLv3)',
            'Operating System :: POSIX',
            'Topic :: Security',
            'Programming Language :: Python :: 2.6',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.2',
            'Programming Language :: Python :: 3.3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
        ],
    test_suite='seccure.tests',
    ),
