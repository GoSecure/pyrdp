#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import asyncio
import logging
from pathlib import Path

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
from pyrdp.mitm.cli import parseTarget, prepareLoggers, validateKeyAndCertificate


class Options(usage.Options):
    # Warning: keep in sync with bin/pyrdp-mitm.py
    optParameters = [
        ["listen", "l", "3389", "Port number to listen on (default: 3389)"],
        ["target", "t", None, "IP:port of the target RDP machine (ex: 192.168.1.10:3390)"],
        ["output", "o", "pyrdp_output", "Output folder for logs and recordings"],
        ["private-key", "k", None, "Path to private key (for SSL)"],
        ["certificate", "c", None, "Path to certificate (for SSL)"],
        ["username", "u", None, "Username that will replace the client's username"],
        ["password", "p", None, "Password that will replace the client's password"],
        ["log-level", "L", "INFO", "Console logging level. Logs saved to file are always verbose. "
                                   "Choices: INFO, DEBUG, WARNING, ERROR, CRITICAL"],
        ["log-filter", "F", "", "Only show logs from this logger name (accepts '*' wildcards)"],
        ["sensor-id", "s", "PyRDP", "Sensor ID (to differentiate multiple instances "
                                    "of the MITM where logs are aggregated at one place)"]]

    optFlags = [["gdi", None, 'Allows GDI passthrough']]


@implementer(IServiceMaker, IPlugin)
class PyRdpMitmServiceMaker(object):
    tapname = "pyrdp"
    description = "Remote Desktop Protocol (RDP) man-in-the-middle"
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a MITMServerFactory
        """
        outDir = Path(options["output"])
        outDir.mkdir(exist_ok = True)

        logLevel = options["log-level"]
        prepareLoggers(logLevel, options["log-filter"], options["sensor-id"], outDir)

        # Warning: only implemented a minimal subset of available config
        #          see bin/pyrdp-mitm.py for the full list
        config = MITMConfig()
        targetHost, targetPort = parseTarget(options["target"])
        config.targetHost = targetHost
        config.targetPort = targetPort
        config.allowGdi = options["gdi"]

        key, certificate = validateKeyAndCertificate(options["private-key"],
                                                     options["certificate"])
        config.privateKeyFileName = key
        config.certificateFileName = certificate

        config.replacementUsername = options["username"]
        config.replacementPassword = options["password"]
        config.outDir = outDir

        return internet.TCPServer(int(options["listen"]), MITMServerFactory(config))


serviceMaker = PyRdpMitmServiceMaker()
