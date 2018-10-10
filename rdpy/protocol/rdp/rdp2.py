from rdpy.core.newlayer import Layer
from rdpy.protocol.gcc.pdu import GCCParser
from rdpy.protocol.mcs.channel import MCSChannelFactory
from rdpy.protocol.mcs.client import MCSClientConnectionObserver, MCSClientRouter
from rdpy.protocol.mcs.layer import MCSLayer
from rdpy.protocol.mcs.user import MCSUserObserver
from rdpy.protocol.rdp.pdu.connection import RDPClientConnectionParser, RDPNegotiationParser, \
    RDPNegotiationResponsePDU, NegotiationProtocols
from rdpy.protocol.rdp.rdp import ServerFactory
from rdpy.protocol.rdp.x224 import ServerTLSContext
from rdpy.protocol.tcp.layer import TCPObserver, TCPLayer
from rdpy.protocol.tpkt.layer import TPKTLayer
from rdpy.protocol.x224.layer import X224Observer, X224Layer


class FakeLayer(Layer):
    def recv(self, data):
        print(data)


class ChannelFactory(MCSChannelFactory):
    def buildChannel(self, mcs, userID, channelID):
        print("Building channel %d (user: %d)" % (channelID, userID))


class AServer(TCPObserver, X224Observer, MCSClientConnectionObserver, MCSUserObserver):
    def __init__(self, tpkt, x224, mcs, router, certificateFileName, privateKeyFileName):
        super(AServer, self).__init__()
        super(AServer, self).__init__()
        super(AServer, self).__init__()
        super(AServer, self).__init__()
        self.tpkt = tpkt
        self.x224 = x224
        self.mcs = mcs
        self.router = router
        self.certificateFileName = certificateFileName
        self.privateKeyFileName = privateKeyFileName
        self.gcc = GCCParser()
        self.rdp = RDPClientConnectionParser()
        self.rdpNegotiationParser = RDPNegotiationParser()

    def connected(self):
        print "Connection established"

    def connectionConfirm(self, pdu):
        print "Connection Confirm received"

    def connectionRequest(self, pdu):
        print "Connection Request received"
        rdp_pdu = self.rdpNegotiationParser.parse(pdu.payload)
        if rdp_pdu.tlsSupported:
            self.x224.sendConnectionConfirm(self.rdpNegotiationParser.write(RDPNegotiationResponsePDU(0x00, NegotiationProtocols.SSL)), source=0x1234)
            self.tpkt.startTLS(ServerTLSContext(privateKeyFileName=self.privateKeyFileName, certificateFileName=self.certificateFileName))
        else:
            raise Exception("bad connection request")


    def disconnectRequest(self, pdu):
        print "Disconnect Request received"

    def error(self, pdu):
        print "Error received"

    def connectResponse(self, pdu):
        print "connect response"

    def disconnectProviderUltimatum(self, pdu):
        print("Disconnect Provider Ultimatum received")

    def attachConfirmed(self, user):
        print "attachconfirmed"

    def attachRefused(self, user):
        print("Could not attach a new user")


class ARDPLayer(Layer):

    def __init__(self, rdpNegotiationParser):
        super(ARDPLayer, self).__init__()
        self.negotiationParser = rdpNegotiationParser

    def recv(self, data):
        pass

    def send(self, payload):
        self.previous.send()


class RDPServerFactory(object, ServerFactory):

    def __init__(self, privateKeyFileName, certificateFileName):
        super(RDPServerFactory, self).__init__()
        self._privateKeyFileName = privateKeyFileName
        self._certificateFileName = certificateFileName

    def buildProtocol(self, addr):
        tcp = TCPLayer()
        tpkt = TPKTLayer()
        x224 = X224Layer()

        router = MCSClientRouter(ChannelFactory())
        mcs = MCSLayer(router)

        tcp.setNext(tpkt)
        tpkt.setNext(x224)
        x224.setNext(mcs)

        observer = AServer(tpkt, x224, mcs, router, self._certificateFileName, self._privateKeyFileName)
        tcp.setObserver(observer)
        x224.setObserver(observer)
        router.setObserver(observer)

        return tcp