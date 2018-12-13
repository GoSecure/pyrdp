#!/usr/bin/env python3
# coding=utf-8

# setuptools MUST be imported first, otherwise we get an error with the ext_modules argument.
import setuptools
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
    packages=setuptools.find_namespace_packages(include=["pyrdp", "pyrdp.*"]),
    ext_modules=[Extension('rle', ['ext/rle.c'])],
    scripts=[
            'bin/pyrdp-clonecert.py',
            'bin/pyrdp-mitm.py',
            'bin/pyrdp-player.py'
    ],
    install_requires=[
            'twisted',
            'pyopenssl',
            'service_identity',
            'qt4reactor',
            'rsa',
            'notify2',
            'pycrypto',
            'appdirs',
            'names',
            'pytz'
    ],
)
