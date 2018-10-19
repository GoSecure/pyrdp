import logging

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from rdpy.core import log
from rdpy.mitm.server import MITMServer


class MITMServerFactory(ServerFactory):
    def __init__(self, targetIP, privateKeyFileName, certificateFileName):
        self._privateKeyFileName = privateKeyFileName
        self._certificateFileName = certificateFileName

    def buildProtocol(self, addr):
        server = MITMServer("127.0.0.2", 3390, self._certificateFileName, self._privateKeyFileName)
        return server.getProtocol()


log.get_logger().setLevel(logging.DEBUG)
reactor.listenTCP(3388, MITMServerFactory("127.0.0.1", None, None))
reactor.run()