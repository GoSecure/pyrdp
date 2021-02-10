#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import asyncio
import logging

# Need to install this reactor before importing other twisted code
from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())
from twisted.internet import reactor

from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm.cli import showConfiguration, configure
from pyrdp.logging import LOGGER_NAMES
import socket


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

    s.bind(('0.0.0.0', config.listenPort))
    s.listen()  # Non-blocking.
    reactor.adoptStreamPort(s.fileno(), socket.AF_INET, MITMServerFactory(config))
    s.close()  # reactor creates a copy of the fd.

    logger.info("MITM Server listening on port %(port)d", {"port": config.listenPort})

    reactor.run()

    logger.info("MITM terminated")
    showConfiguration(config)


if __name__ == "__main__":
    main()
