#!/usr/bin/env python3
# coding=utf-8

#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

# setuptools MUST be imported first, otherwise we get an error with the ext_modules argument.
import setuptools
from distutils.core import Extension, setup

setup(name='pyrdp',
    version='0.4.2.dev0',
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
        'bin/pyrdp-player.py'
    ],
    install_requires=[
        'appdirs',
        'cryptography',
        'names',
        'pyasn1',
        'pycryptodome',
        'pyopenssl>=19,<20',
        'pytz',
        'rsa',
        'scapy',
        'service_identity',
        'twisted',
    ],
    extras_require={
        "full": ['PySide2', 'dbus-python;platform_system!="Windows"', 'notify2;platform_system!="Windows"']
    }
)
