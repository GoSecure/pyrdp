#!/usr/bin/env python3
# coding=utf-8

from distutils.core import Extension, setup

setup(name='pyrdp',
    version='1.0.0',
    description='Remote Desktop Protocol Man-in-the-Middle and library for Python3',
    long_description="""
    to do.
    """,
    author='Émilio Gonzalez, Francis Labelle',
    author_email='egg997@gmail.com, flabelle@gosecure.ca',
    url='https://github.com/GoSecure/rdpy',
    packages=[
        'pyrdp',
        'pyrdp.core',
        'pyrdp.logging',
        'pyrdp.security',
        'pyrdp.ui',

        'pyrdp.enum',
        'pyrdp.enum.virtual_channel',
        'pyrdp.layer',
        'pyrdp.layer.rdp',
        'pyrdp.layer.rdp.virtual_channel',
        'pyrdp.mcs',
        'pyrdp.mitm',
        'pyrdp.mitm.virtual_channel',
        'pyrdp.parser',
        'pyrdp.parser.rdp',
        'pyrdp.parser.rdp.virtual_channel',
        'pyrdp.pdu',
        'pyrdp.pdu.rdp',
        'pyrdp.pdu.rdp.virtual_channel',
        'pyrdp.player',
        'pyrdp.recording',
    ],
    ext_modules=[Extension('rle', ['ext/rle.c'])],
    scripts=[
            'bin/pyrdp-rdpmitm.py',
            'bin/pyrdp-player.py'
    ],
    install_requires=[
            'twisted',
            'pyopenssl',
            'service_identity',
            'qt4reactor',
            'rsa',
            'pyasn1',
            'notify2',
            'pycrypto',
            'appdirs',
            'names',
            'pytz'
    ],
)
