#!/usr/bin/env python3
# coding=utf-8

#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

# setuptools MUST be imported first, otherwise we get an error with the ext_modules argument.
import setuptools
from distutils.core import Extension, setup

setup(name='pyrdp',
    version='1.1.0',
    description='Remote Desktop Protocol Man-in-the-Middle and library for Python 3',
    long_description="""Remote Desktop Protocol Man-in-the-Middle and library for Python 3""",
    author='Émilio Gonzalez, Francis Labelle',
    author_email='egg997@gmail.com, flabelle@gosecure.ca',
    url='https://github.com/GoSecure/pyrdp',
    packages=setuptools.find_packages(include=["pyrdp", "pyrdp.*"]),
    package_data={
        "pyrdp": ["mitm/crawler_config/*.txt"],
        "": ["*.default.ini"]
    },
    ext_modules=[Extension('rle', ['ext/rle.c'])],
    scripts=[
        'bin/pyrdp-clonecert.py',
        'bin/pyrdp-mitm.py',
        'bin/pyrdp-player.py',
        'bin/pyrdp-convert.py',
    ],
    install_requires=[
        'appdirs>=1,<2',
        'cryptography>=3.3.2,<4',
        'names>=0,<1',
        'progressbar2>=3.20,<4',
        'pyasn1>=0,<1',
        'pycryptodome>=3.5,<4',
        'pyopenssl>=19,<20',
        'pytz',
        'rsa>=4,<5',
        'scapy>=2.4,<3',
        'service_identity>=18',
        'twisted>=18',
    ],
    extras_require={
        "full": [
            'wheel>=0.34.2',
            'av>=8',
            'pillowcase>=2',
            'PySide2>=5.12,<6',
            'dbus-python>=1.2<1.3;platform_system!="Windows"',
            'notify2>=0.3,<1;platform_system!="Windows"'
        ]
    }
)
