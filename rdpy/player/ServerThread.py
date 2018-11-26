import asyncio
import logging
from typing import Callable

from PyQt4.QtCore import QThread


class ServerThread(QThread):
    """
    Thread for receiving live connection data.
    """

    def __init__(self, host: str, port: int, protocolFactory: Callable[[], asyncio.Protocol]):
        """
        :param host: host to bind to.
        :param port: port to listen on.
        :param protocolFactory: asyncio protocol factory.
        """
        QThread.__init__(self)
        self.host = host
        self.port = port
        self.protocolFactory = protocolFactory
        self.loop = asyncio.new_event_loop()

    def run(self):
        asyncio.set_event_loop(self.loop)

        server = self.loop.create_server(self.protocolFactory, host=self.host, port=self.port)
        server = self.loop.run_until_complete(server)

        logging.info("Listening on %s:%d" % (self.host, self.port))
        self.loop.run_forever()

    def stop(self):
        self.loop.call_soon_threadsafe(self.stopLoop)

    def stopLoop(self):
        self.loop.stop()