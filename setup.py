#!/usr/bin/env python3
# coding=utf-8

#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2023 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from setuptools import Extension, setup

setup(
    ext_modules=[Extension('rle', ['ext/rle.c'])],
)
