#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import asyncio
from pathlib import Path
import sys

# need to install this reactor before importing other twisted code
from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet
from zope.interface import implementer

from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm import MITMConfig
from pyrdp.mitm.cli import configure


class Options(usage.Options):
    optFlags = []
    optParameters = []
    def parseOptions(self, args):
        self['config'] = configure(args)


@implementer(IServiceMaker, IPlugin)
class PyRdpMitmServiceMaker(object):
    tapname = "pyrdp"
    description = "Remote Desktop Protocol (RDP) man-in-the-middle"
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a MITMServerFactory
        """
        config = options['config']
        return internet.TCPServer(config.listenPort, MITMServerFactory(config))

serviceMaker = PyRdpMitmServiceMaker()
