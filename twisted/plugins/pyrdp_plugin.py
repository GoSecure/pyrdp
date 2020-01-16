#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import asyncio
from pathlib import Path

from zope.interface import implementer

from twisted.internet import asyncioreactor
asyncioreactor.install(asyncio.get_event_loop())

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import service, internet
from twisted.internet import endpoints, protocol, reactor

from pyrdp.core import parseTarget, validateKeyAndCertificate
from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm import MITMConfig


class Options(usage.Options):
    # Warning: keep in sync with bin/pyrdp-mitm.py
    optParameters = [
        ["listen", "l", "tcp:3389", "Port number to listen on (default: tcp:3389)"],
        ["target", "t", None, "IP:port of the target RDP machine (ex: 192.168.1.10:3390)"],
        ["output", "o", "pyrdp_output", "Output folder for logs and recordings"],
        ["private-key", "k", None, "Path to private key (for SSL)"],
        ["certificate", "c", None, "Path to certificate (for SSL)"],
        ["username", "u", None, "Username that will replace the client's username"],
        ["password", "p", None, "Password that will replace the client's password"]]

class SetupService(service.Service):
    name = 'Setup Service'

    def __init__(self, reactor):
        self.reactor = reactor

    def startService(self):
        """
        Custom initialisation code goes here.
        """
        self.reactor.callLater(3, self.done)

    def done(self):
        pass


@implementer(IServiceMaker, IPlugin)
class PyRdpMitmServiceMaker(object):
    tapname = "pyrdp"
    description = "Remote Desktop Protocol (RDP) man-in-the-middle"
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in myproject.
        """

        # Warning: only implemented a minimal subset of available config
        #          see bin/pyrdp-mitm.py for the full list
        config = MITMConfig()
        targetHost, targetPort = parseTarget(options["target"])
        config.targetHost = targetHost
        config.targetPort = targetPort

        key, certificate = validateKeyAndCertificate(options["private-key"],
                                                     options["certificate"])
        config.privateKeyFileName = key
        config.certificateFileName = certificate

        config.replacementUsername = options["username"]
        config.replacementPassword = options["password"]
        config.outDir = Path(options["output"])
        config.outDir.mkdir(exist_ok = True)

        endpoint = endpoints.serverFromString(reactor, options["listen"])
        server_service = internet.StreamServerEndpointService(endpoint, MITMServerFactory(config))
        server_service.setName("PyRDP Server")

        setup_service = SetupService(reactor)

        ms = service.MultiService()
        server_service.setServiceParent(ms)
        setup_service.setServiceParent(ms)
        return ms

        #return internet.TCPServer(3389, MITMServerFactory(config))
        #return internet.StreamServerEndpointService(targetPort, MITMServerFactory(config))
        #return reactor.listenTCP(targetPort, MITMServerFactory(config))


serviceMaker = PyRdpMitmServiceMaker()