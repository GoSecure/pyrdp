from rdpy.core import log
from rdpy.core.newlayer import Layer
from rdpy.enum.mcs import MCSResult
from rdpy.enum.rdp import NegotiationProtocols, RDPSecurityHeaderType
from rdpy.layer.mcs import MCSLayer
from rdpy.layer.rdp.licensing import RDPLicensingLayer
from rdpy.layer.rdp.security import RDPSecurityLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.layer.x224 import X224Layer
from rdpy.parser.gcc import GCCParser
from rdpy.parser.rdp import RDPNegotiationParser, RDPClientConnectionParser, RDPServerConnectionParser, \
    RDPClientInfoParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSConnectResponsePDU, MCSDomainParams
from rdpy.pdu.rdp.connection import RDPNegotiationResponsePDU, RDPServerDataPDU, ServerCoreData, ServerNetworkData, \
    ServerSecurityData
from rdpy.pdu.rdp.licensing import RDPLicenseErrorAlertPDU, RDPLicenseBinaryBlob
from rdpy.protocol.mcs.channel import MCSChannelFactory, MCSServerChannel
from rdpy.protocol.mcs.client import MCSClientConnectionObserver
from rdpy.protocol.mcs.server import MCSServerRouter, MCSUserIDGenerator
from rdpy.protocol.mcs.user import MCSUserObserver
from rdpy.protocol.rdp.lic import ErrorCode, StateTransition, BinaryBlobType
from rdpy.protocol.rdp.rdp import ServerFactory
from rdpy.protocol.rdp.t125.mcs import Channel
from rdpy.protocol.rdp.x224 import ServerTLSContext


class FakeLayer(Layer):
    def recv(self, data):
        print(data)


class AServer(MCSClientConnectionObserver, MCSUserObserver, MCSChannelFactory):
    def __init__(self, tpkt, x224, mcs, certificateFileName, privateKeyFileName):

        MCSClientConnectionObserver.__init__(self)
        MCSUserObserver.__init__(self)
        self.use_tls = False
        self.tpkt = tpkt
        self.x224 = x224
        self.mcs = mcs
        self.io = IOChannel()
        self.ioSecurityLayer = None
        self.licensingLayer = RDPLicensingLayer()
        self.certificateFileName = certificateFileName
        self.privateKeyFileName = privateKeyFileName
        self.gcc = GCCParser()
        self.rdpClientInfoParser = RDPClientInfoParser()
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

    def onClientInfoReceived(self, pdu):
        clientInfoPDU = self.rdpClientInfoParser.parse(pdu)
        licenseErrorAlertPDU = RDPLicenseErrorAlertPDU(0x00, ErrorCode.STATUS_VALID_CLIENT, StateTransition.ST_NO_TRANSITION,
                                                       RDPLicenseBinaryBlob(BinaryBlobType.BB_ERROR_BLOB, ""))
        self.ioSecurityLayer.send(self.licensingLayer.parser.write(licenseErrorAlertPDU), isLicensing=True)

    def buildChannel(self, mcs, userID, channelID):
        if channelID == Channel.MCS_GLOBAL_CHANNEL:
            self.ioSecurityLayer = RDPSecurityLayer(RDPSecurityHeaderType.BASIC, None)
            self.ioSecurityLayer.setNext(self.io)
            self.ioSecurityLayer.setObserver(self)
            channel = MCSServerChannel(mcs, userID, channelID)
            channel.setNext(self.ioSecurityLayer)
            return channel
        else:
            log.debug("Ignoring building channel {} for user {}".format(channelID, userID))



class IOChannel(Layer):
    def __init__(self):
        Layer.__init__(self)

    def recv(self, data):
        log.info("Security Exchange result: %s" % data.encode('hex'))
        pass


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

        tcp.setNext(tpkt)
        tpkt.setNext(x224)
        x224.setNext(mcs)

        observer = AServer(tpkt, x224, mcs, self._certificateFileName, self._privateKeyFileName)
        router = MCSServerRouter(mcs, observer, MCSUserIDGenerator([1002, 1003, 1004, 1005, 1006]))
        tcp.createObserver(onConnection=observer.onConnection)
        x224.createObserver(onConnectionRequest=observer.onConnectionRequest)
        mcs.setObserver(router)
        router.setObserver(observer)

        return tcp