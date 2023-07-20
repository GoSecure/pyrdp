#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
# Need to install this reactor before importing any other code
import asyncio
import sys
# We need a special asyncio loop on Windows above Python 3.8. See #316
if (sys.platform == "win32" and sys.version_info.major == 3 and sys.version_info.minor >= 8):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from twisted.internet import asyncioreactor
asyncioreactor.install(asyncio.new_event_loop())

import logging
import os
import socket

from twisted.internet import reactor

from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm.cli import showConfiguration, configure
from pyrdp.logging import LOGGER_NAMES


def main():
    config = configure()
    logger = logging.getLogger(LOGGER_NAMES.PYRDP)

    # Create a listening socket to accept connections.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)

    if config.transparent:
        try:
            if not s.getsockopt(socket.SOL_IP, socket.IP_TRANSPARENT):
                s.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            logger.warning('Unable to set transparent socket. Are you running as root?')

    s.bind((config.listenAddress, config.listenPort))
    s.listen()  # Non-blocking.
    reactor.adoptStreamPort(s.fileno(), socket.AF_INET, MITMServerFactory(config))
    s.close()  # reactor creates a copy of the fd.

    message = "MITM Server listening on %(address)s:%(port)d"
    params = {"address": config.listenAddress, "port": config.listenPort}

    if "HOST_IP" in os.environ:
        message += ". Host IP: %(host_ip)s"
        params["host_ip"] = os.environ["HOST_IP"]

    logger.info(message, params)

    reactor.run()

    logger.info("MITM terminated")
    showConfiguration(config)


if __name__ == "__main__":
    main()
