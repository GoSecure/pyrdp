from rdpy.core import log
from rdpy.core.newlayer import Layer
from rdpy.enum.mcs import MCSResult
from rdpy.parser.gcc import GCCParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSConnectResponsePDU
from rdpy.protocol.mcs.channel import MCSChannelFactory
from rdpy.protocol.mcs.client import MCSClientConnectionObserver
from rdpy.protocol.mcs.layer import MCSLayer
from rdpy.protocol.mcs.pdu import MCSDomainParams
from rdpy.protocol.mcs.server import MCSServerRouter, MCSUserIDGenerator
from rdpy.protocol.mcs.user import MCSUserObserver
from rdpy.protocol.rdp.pdu.connection import RDPClientConnectionParser, RDPNegotiationParser, \
    RDPNegotiationResponsePDU, NegotiationProtocols, RDPServerDataPDU, ServerCoreData, ServerNetworkData, \
    ServerSecurityData, RDPServerConnectionParser
from rdpy.protocol.rdp.rdp import ServerFactory
from rdpy.protocol.rdp.t125.mcs import Channel
from rdpy.protocol.rdp.x224 import ServerTLSContext
from rdpy.protocol.tcp.layer import TCPLayer
from rdpy.protocol.tpkt.layer import TPKTLayer
from rdpy.protocol.x224.layer import X224Layer


class FakeLayer(Layer):
    def recv(self, data):
        print(data)


class ChannelFactory(MCSChannelFactory):
    def buildChannel(self, mcs, userID, channelID):
        print("Building channel %d (user: %d)" % (channelID, userID))


class AServer(MCSClientConnectionObserver, MCSUserObserver):
    def __init__(self, tpkt, x224, mcs, router, certificateFileName, privateKeyFileName):

        MCSClientConnectionObserver.__init__(self)
        MCSUserObserver.__init__(self)
        self.use_tls = False
        self.tpkt = tpkt
        self.x224 = x224
        self.mcs = mcs
        self.router = router
        self.certificateFileName = certificateFileName
        self.privateKeyFileName = privateKeyFileName
        self.gcc = GCCParser()
        self.rdpClientConnectionParser = RDPClientConnectionParser()
        self.rdpServerConnectionParser = RDPServerConnectionParser()
        self.rdpNegotiationParser = RDPNegotiationParser()

    def connectionReceived(self, pdu):
        """
        Parse the ClientData PDU and send a ServerData PDU back.
        :param pdu: The GCC ConferenceCreateResponse PDU that contains the ClientData PDU.
        """
        log.info("Connection received")
        if self.use_tls:
            log.get_ssl_logger().info(self.tpkt.previous.transport.protocol._tlsConnection.client_random(),
                                      self.tpkt.previous.transport.protocol._tlsConnection.master_key())
        gccConferenceCreateRequestPDU = self.gcc.parse(pdu.payload)
        rdpClientDataPdu = self.rdpClientConnectionParser.parse(gccConferenceCreateRequestPDU.payload)
        serverCoreData = ServerCoreData(11111, 0, 0)
        if rdpClientDataPdu.networkData is not None:
            channels = [0 for _ in rdpClientDataPdu.networkData.channelDefinitions]
        else:
            channels = []
        serverNetworkData = ServerNetworkData(Channel.MCS_GLOBAL_CHANNEL,
                                              channels)
        serverSecurityData = ServerSecurityData(0, 0, None, None)
        rdpServerDataPdu = self.rdpServerConnectionParser.write(RDPServerDataPDU(serverCoreData, serverSecurityData, serverNetworkData))
        gccCreateResponsePDU = self.gcc.write(GCCConferenceCreateResponsePDU(GCCParser.NODE_ID, 1, 0, rdpServerDataPdu))
        self.mcs.send(MCSConnectResponsePDU(MCSResult.RT_SUCCESSFUL, 0, MCSDomainParams.createTarget(34, 3), gccCreateResponsePDU))
        return True

    def onConnection(self):
        print "Connection established"

    def onConnectionRequest(self, pdu):
        print "Connection Request received"
        rdp_pdu = self.rdpNegotiationParser.parse(pdu.payload)
        if rdp_pdu.tlsSupported:
            self.x224.sendConnectionConfirm(self.rdpNegotiationParser.write(RDPNegotiationResponsePDU(0x00, NegotiationProtocols.SSL)), source=0x1234)
            self.tpkt.startTLS(ServerTLSContext(privateKeyFileName=self.privateKeyFileName, certificateFileName=self.certificateFileName))
            self.use_tls = True
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


class RDPServerFactory(object, ServerFactory):

    def __init__(self, privateKeyFileName, certificateFileName):
        super(RDPServerFactory, self).__init__()
        self._privateKeyFileName = privateKeyFileName
        self._certificateFileName = certificateFileName

    def buildProtocol(self, addr):
        tcp = TCPLayer()
        tpkt = TPKTLayer()
        x224 = X224Layer()

        mcs = MCSLayer()
        router = MCSServerRouter(mcs, ChannelFactory(), MCSUserIDGenerator([1002, 1003, 1004, 1005, 1006]))

        tcp.setNext(tpkt)
        tpkt.setNext(x224)
        x224.setNext(mcs)

        observer = AServer(tpkt, x224, mcs, router, self._certificateFileName, self._privateKeyFileName)
        tcp.createObserver(onConnection=observer.onConnection)
        x224.createObserver(onConnectionRequest=observer.onConnectionRequest)
        mcs.setObserver(router)
        router.setObserver(observer)

        return tcp