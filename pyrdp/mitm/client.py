from socket import socket
from typing import BinaryIO, Dict

from pyrdp.core.helper_methods import getLoggerPassFilters
from pyrdp.core.ssl import ClientTLSContext
from pyrdp.enum import ClientInfoFlags, ParserMode, PlayerMessageType, SegmentationPDUType, VirtualChannelName
from pyrdp.layer import ClipboardLayer, DeviceRedirectionLayer, FastPathLayer, GCCClientConnectionLayer, \
    MCSClientConnectionLayer, MCSLayer, RawLayer, RDPClientConnectionLayer, RDPDataLayer, RDPSecurityLayer, \
    SegmentationLayer, TLSSecurityLayer, TPKTLayer, TwistedTCPLayer, VirtualChannelLayer, X224Layer
from pyrdp.logging import LOGGER_NAMES, RC4LoggingObserver
from pyrdp.mcs.channel import MCSChannelFactory, MCSClientChannel
from pyrdp.mcs.client import MCSClientRouter
from pyrdp.mcs.user import MCSUserObserver
from pyrdp.mitm.observer import MITMFastPathObserver, MITMSlowPathObserver
from pyrdp.mitm.virtual_channel.clipboard import ActiveClipboardChannelObserver
from pyrdp.mitm.virtual_channel.device_redirection import ClientPassiveDeviceRedirectionObserver
from pyrdp.mitm.virtual_channel.virtual_channel import MITMVirtualChannelObserver
from pyrdp.parser.rdp.fastpath import createFastPathParser
from pyrdp.parser.rdp.negotiation import RDPNegotiationRequestParser, RDPNegotiationResponseParser
from pyrdp.pdu.gcc import GCCConferenceCreateResponsePDU
from pyrdp.pdu.rdp.client_info import RDPClientInfoPDU
from pyrdp.recording.observer import RecordingFastPathObserver, RecordingSlowPathObserver
from pyrdp.recording.recorder import FileLayer, Recorder, SocketLayer
from pyrdp.security import RC4CrypterProxy, SecuritySettings


class MITMClient(MCSChannelFactory, MCSUserObserver):
    def __init__(self, server, fileHandle: BinaryIO, livePlayerSocket: socket,
                 replacementUsername=None, replacementPassword=None):
        MCSChannelFactory.__init__(self)
        self.log = getLoggerPassFilters(f"{LOGGER_NAMES.MITM_CONNECTIONS}.{server.getSessionId()}.client")
        self.log.addFilter(server.metadataFilter)

        self.replacementUsername = replacementUsername
        self.replacementPassword = replacementPassword

        self.server = server
        self.channelMap: Dict[int, str] = {}
        self.channelDefinitions = []
        self.channelObservers = {}
        self.deviceRedirectionObserver = None
        self.useTLS = False
        self.user = None
        self.fastPathObserver = None
        self.conferenceCreateResponse = None
        self.serverData = None
        self.crypter = RC4CrypterProxy()

        rc4Log = getLoggerPassFilters(f"{self.log.name}.rc4")
        self.securitySettings = SecuritySettings(SecuritySettings.Mode.CLIENT)
        self.securitySettings.addObserver(self.crypter)
        self.securitySettings.addObserver(RC4LoggingObserver(rc4Log))

        self.tcp = TwistedTCPLayer()
        self.tcp.createObserver(onConnection=self.startConnection, onDisconnection=self.onDisconnection)

        self.segmentation = SegmentationLayer()
        self.segmentation.createObserver(onUnknownHeader=self.onUnknownTPKTHeader)

        self.tpkt = TPKTLayer()

        self.x224 = X224Layer()
        self.x224.createObserver(onConnectionConfirm=self.onConnectionConfirm, onDisconnectRequest=self.onDisconnectRequest)

        self.mcs = MCSLayer()
        self.router = MCSClientRouter(self.mcs, self)
        self.mcs.addObserver(self.router)
        self.router.createObserver(onConnectResponse=self.onConnectResponse, onDisconnectProviderUltimatum=self.onDisconnectProviderUltimatum)

        self.mcsConnect = MCSClientConnectionLayer(self.mcs)

        self.gccConnect = GCCClientConnectionLayer(b"1")
        self.gccConnect.createObserver(onPDUReceived=self.onConferenceCreateResponse)

        self.rdpConnect = RDPClientConnectionLayer()
        self.rdpConnect.createObserver(onPDUReceived=self.onServerData)

        self.securityLayer = None
        self.io = RDPDataLayer()
        self.fastPathLayer = None

        self.tcp.setNext(self.segmentation)
        self.segmentation.attachLayer(SegmentationPDUType.TPKT, self.tpkt)
        self.tpkt.setNext(self.x224)
        self.x224.setNext(self.mcs)
        self.mcsConnect.setNext(self.gccConnect)
        self.gccConnect.setNext(self.rdpConnect)

        record_layers = [FileLayer(fileHandle)]

        if livePlayerSocket is not None:
            record_layers.append(SocketLayer(livePlayerSocket))

        self.recorder = Recorder(record_layers)

    def getProtocol(self):
        return self.tcp

    def startConnection(self):
        """
        Start the connection sequence to the target machine.
        """
        self.log.debug("TCP connected")
        negotiation = self.server.getNegotiationPDU()
        parser = RDPNegotiationRequestParser()
        self.x224.sendConnectionRequest(parser.write(negotiation))

    def onDisconnection(self, reason):
        self.log.debug(f"Connection closed: {reason}")
        self.server.disconnect()
        self.log.removeFilter(self.server.metadataFilter)

    def onDisconnectRequest(self, pdu):
        self.log.debug("X224 Disconnect Request received")
        self.disconnect()

    def disconnect(self):
        self.log.debug("Disconnecting")
        self.tcp.disconnect()

    def onUnknownTPKTHeader(self, header):
        self.log.error("Closing the connection because an unknown TPKT header was received. Header: 0x%(header)02lx",
                       {"header": header})
        self.disconnect()

    def onConnectionConfirm(self, pdu):
        """
        Called when the X224 layer is connected.
        """
        self.log.debug("Connection Confirm received")

        parser = RDPNegotiationResponseParser()
        response = parser.parse(pdu.payload)

        if response.tlsSelected:
            self.tcp.startTLS(ClientTLSContext())
            self.useTLS = True

        self.server.onConnectionConfirm(pdu)

    def onConnectInitial(self, gccConferenceCreateRequest, clientData):
        """
        Called when a Connect Initial PDU is received.
        :param gccConferenceCreateRequest: the conference create request.
        :param clientData: the RDPClientDataPDU.
        """
        self.log.debug("Sending Connect Initial")

        if clientData.networkData:
            self.channelDefinitions = clientData.networkData.channelDefinitions

        self.gccConnect.conferenceName = gccConferenceCreateRequest.conferenceName
        self.rdpConnect.send(clientData)

    def onConnectResponse(self, pdu):
        """
        Called when an MCS Connect Response PDU is received.
        """
        if pdu.result != 0:
            self.log.error("MCS Connection Failed")
            self.server.onConnectResponse(pdu, None)
        else:
            self.log.debug("MCS Connection Successful")
            self.mcsConnect.recv(pdu)
            self.server.onConnectResponse(pdu, self.serverData)

    def onConferenceCreateResponse(self, pdu):
        """
        Called when a GCC Conference Create Response is received.
        :param pdu: the conference response PDU
        :type pdu: GCCConferenceCreateResponsePDU
        """
        self.conferenceCreateResponse = pdu

    def onServerData(self, serverData):
        """
        Called when the server data from the GCC Conference Create Response is received.
        """
        self.serverData = serverData
        self.securitySettings.generateClientRandom()
        self.securitySettings.serverSecurityReceived(serverData.security)

        self.channelMap[self.serverData.network.mcsChannelID] = "I/O"

        for index in range(len(serverData.network.channels)):
            channelID = serverData.network.channels[index]
            self.channelMap[channelID] = self.channelDefinitions[index].name

    def onAttachUserRequest(self):
        self.user = self.router.createUser()
        self.user.addObserver(self)
        self.user.attach()

    def onAttachConfirmed(self, user):
        # MCS Attach User Confirm successful
        self.server.onAttachConfirmed(user)

    def onAttachRefused(self, user, result):
        # MCS Attach User Confirm failed
        self.server.onAttachRefused(user, result)

    def onChannelJoinRequest(self, pdu):
        self.mcs.send(pdu)

    def buildChannel(self, mcs, userID, channelID):
        channelName = self.channelMap.get(channelID, None)
        channelLog = channelName + " (%d)" % channelID if channelName else channelID
        self.log.debug("building channel {} for user {}".format(channelLog, userID))

        if channelName == "I/O":
            channel = self.buildIOChannel(mcs, userID, channelID)
        elif channelName == VirtualChannelName.CLIPBOARD:
            channel = self.buildClipboardChannel(mcs, userID, channelID)
        elif channelName == VirtualChannelName.DEVICE_REDIRECTION:
            channel = self.buildDeviceRedirectionChannel(mcs, userID, channelID)
        else:
            channel = self.buildVirtualChannel(mcs, userID, channelID)

        self.server.onChannelJoinAccepted(userID, channelID)
        return channel

    def createSecurityLayer(self):
        encryptionMethod = self.serverData.security.encryptionMethod

        if self.useTLS:
            return TLSSecurityLayer()
        else:
            return RDPSecurityLayer.create(encryptionMethod, self.crypter)

    def buildVirtualChannel(self, mcs, userID, channelID) -> MCSClientChannel:
        channel = MCSClientChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        rawLayer = RawLayer()

        channel.setNext(securityLayer)
        securityLayer.setNext(rawLayer)

        observer = MITMVirtualChannelObserver(rawLayer)
        rawLayer.addObserver(observer)
        self.channelObservers[channelID] = observer

        return channel

    def buildClipboardChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSClientChannel:
        """
        :param userID: The mcs user that builds the channel
        :param channelID: The channel ID to use to communicate in that channel
        :return: MCSClientChannel that handles the Clipboard virtual channel traffic from the server to the MITM.
        """
        # Create all necessary layers
        channel = MCSClientChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        virtualChannelLayer = VirtualChannelLayer()
        clipboardLayer = ClipboardLayer()

        # Link layers together in the good order: MCS --> Security --> VirtualChannel --> Clipboard
        channel.setNext(securityLayer)
        securityLayer.setNext(virtualChannelLayer)
        virtualChannelLayer.setNext(clipboardLayer)

        # Create and link the MITM Observer for the client side to the clipboard layer.
        activeClipboardObserver = ActiveClipboardChannelObserver(clipboardLayer, self.recorder, self.log)
        clipboardLayer.addObserver(activeClipboardObserver)

        self.channelObservers[channelID] = activeClipboardObserver

        return channel

    def buildDeviceRedirectionChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSClientChannel:
        """
        :param userID: The mcs user that builds the channel
        :param channelID: The channel ID to use to communicate in that channel
        :return: MCSClientChannel that handles the Device redirection virtual channel traffic from the server to the MITM.
        """
        # Create all necessary layers
        channel = MCSClientChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        virtualChannelLayer = VirtualChannelLayer(activateShowProtocolFlag=False)
        deviceRedirectionLayer = DeviceRedirectionLayer()

        # Link layers together in the good order: MCS --> Security --> VirtualChannel --> DeviceRedirection
        channel.setNext(securityLayer)
        securityLayer.setNext(virtualChannelLayer)
        virtualChannelLayer.setNext(deviceRedirectionLayer)

        # Create and link the MITM Observer for the client side to the device redirection layer.
        self.deviceRedirectionObserver = ClientPassiveDeviceRedirectionObserver(deviceRedirectionLayer, self.recorder,
                                                                                self.log)
        deviceRedirectionLayer.addObserver(self.deviceRedirectionObserver)

        self.channelObservers[channelID] = self.deviceRedirectionObserver

        return channel

    def buildIOChannel(self, mcs: MCSLayer, userID: int, channelID: int) -> MCSClientChannel:
        encryptionMethod = self.serverData.security.encryptionMethod
        self.securityLayer = self.createSecurityLayer()
        self.securityLayer.createObserver(onLicensingDataReceived=self.onLicensingDataReceived)

        slowPathObserver = MITMSlowPathObserver(self.log, self.io)
        self.io.addObserver(slowPathObserver)
        self.io.addObserver(RecordingSlowPathObserver(self.recorder))
        self.channelObservers[channelID] = slowPathObserver

        fastPathParser = createFastPathParser(self.useTLS, encryptionMethod, self.crypter, ParserMode.CLIENT)
        self.fastPathLayer = FastPathLayer(fastPathParser)
        self.fastPathObserver = MITMFastPathObserver(self.log, self.fastPathLayer)
        self.fastPathLayer.addObserver(self.fastPathObserver)
        self.fastPathLayer.addObserver(RecordingFastPathObserver(self.recorder, PlayerMessageType.FAST_PATH_OUTPUT))

        channel = MCSClientChannel(mcs, userID, channelID)
        channel.setNext(self.securityLayer)
        self.securityLayer.setNext(self.io)

        self.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.fastPathLayer)

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = True
        elif encryptionMethod != 0:
            self.log.debug("Sending Security Exchange")
            self.io.previous.sendSecurityExchange(self.securitySettings.encryptClientRandom())

        return channel

    def onChannelJoinRefused(self, user, result, channelID):
        self.server.onChannelJoinRefused(user, result, channelID)

    def onClientInfoPDUReceived(self, pdu: RDPClientInfoPDU):

        # If set, replace the provided username and password to connect the user regardless of
        # the credentials they entered.
        if self.replacementUsername is not None:
            pdu.username = self.replacementUsername
        if self.replacementPassword is not None:
            pdu.password = self.replacementPassword

        # Tell the server we don't want compression (unsure of the effectiveness of these flags)
        pdu.flags &= ~ClientInfoFlags.INFO_COMPRESSION
        pdu.flags &= ~ClientInfoFlags.INFO_CompressionTypeMask
        self.log.debug("Sending Client Info: {}".format(pdu))
        self.securityLayer.sendClientInfo(pdu)

    def onLicensingDataReceived(self, data):
        self.log.debug("Licensing data received")

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = False

        self.server.onLicensingDataReceived(data)

    def onDisconnectProviderUltimatum(self, pdu):
        self.log.debug("Disconnect Provider Ultimatum received")
        self.server.sendDisconnectProviderUltimatum(pdu)

    def getChannelObserver(self, channelID):
        return self.channelObservers[channelID]

    def getFastPathObserver(self):
        return self.fastPathObserver
