import logging

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from rdpy.core import log
from rdpy.mitm.server import MITMServer


class MITMServerFactory(ServerFactory):
    def __init__(self, targetHost, targetPort, privateKeyFileName, certificateFileName):
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.privateKeyFileName = privateKeyFileName
        self.certificateFileName = certificateFileName

    def buildProtocol(self, addr):
        server = MITMServer(self.targetHost, self.targetPort, self.certificateFileName, self.privateKeyFileName)
        return server.getProtocol()


log.get_logger().setLevel(logging.DEBUG)
reactor.listenTCP(3388, MITMServerFactory("127.0.0.2", 3390, None, None))
reactor.run()