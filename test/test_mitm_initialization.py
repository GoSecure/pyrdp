#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Integration test for the initialization of pyrdp-mitm.py.
It could be enhanced with relevant assertions but for now only executes the code to catch
potential basic errors/import problems.
"""
from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm.cli import configure


if __name__ == "__main__":
    config = configure()
    server_factory = MITMServerFactory(config)
    server_factory.buildProtocol(addr=None)
