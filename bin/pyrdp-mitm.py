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

from pyrdp.core import settings
from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm import MITMConfig, DEFAULTS
from pyrdp.mitm.cli import showConfiguration, configure
from pyrdp.logging import LOGGER_NAMES


def main():
    config = configure()
    reactor.listenTCP(config.listenPort, MITMServerFactory(config))
    logger = logging.getLogger(LOGGER_NAMES.PYRDP)

    logger.info("MITM Server listening on port %(port)d", {"port": config.listenPort})
    reactor.run()

    logger.info("MITM terminated")
    showConfiguration(config)


if __name__ == "__main__":
    main()
