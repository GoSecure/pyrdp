#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import logging
from typing import Callable

from PySide2.QtCore import QThread

from pyrdp.logging import LOGGER_NAMES


class LiveThread(QThread):
    """
    Thread for receiving live connection data.
    """

    def __init__(self, host: str, port: int, protocolFactory: Callable[[], asyncio.Protocol]):
        """
        :param host: host to bind to.
        :param port: port to listen on.
        :param protocolFactory: asyncio protocol factory.
        """
        super().__init__()
        self.host = host
        self.port = port
        self.protocolFactory = protocolFactory
        self.loop = asyncio.new_event_loop()

    def run(self):
        asyncio.set_event_loop(self.loop)

        server = self.loop.create_server(self.protocolFactory, host=self.host, port=self.port)
        self.loop.run_until_complete(server)

        logging.getLogger(LOGGER_NAMES.PLAYER).info("Listening for connections on %(listenHost)s:%(listenPort)d", {"listenHost": self.host, "listenPort": self.port})
        self.loop.run_forever()

    def stop(self):
        self.loop.call_soon_threadsafe(self.stopLoop)

    def stopLoop(self):
        self.loop.stop()