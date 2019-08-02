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
    version='0.2.0',
    description='Remote Desktop Protocol Man-in-the-Middle and library for Python 3',
    long_description="""Remote Desktop Protocol Man-in-the-Middle and library for Python 3""",
    author='Émilio Gonzalez, Francis Labelle',
    author_email='egg997@gmail.com, flabelle@gosecure.ca',
    url='https://github.com/GoSecure/pyrdp',
    packages=setuptools.find_packages(include=["pyrdp", "pyrdp.*"]),
    package_data={"pyrdp": ["mitm/crawler_config/*.txt"]},
    ext_modules=[Extension('rle', ['ext/rle.c'])],
    scripts=[
        'bin/pyrdp-clonecert.py',
        'bin/pyrdp-mitm.py',
        'bin/pyrdp-player.py'
    ],
    install_requires=[
        'appdirs',
        'cryptography',
        'dbus-python',
        'names',
        'notify2',
        'pyasn1',
        'pycrypto',
        'pyopenssl',
        'PySide2',
        'pytz',
        'rsa',
        'service_identity',
        'twisted',
    ],
)