import logging
import pprint

from rdpy.core.crypto import SecuritySettings, RC4CrypterProxy
from rdpy.enum.core import ParserMode
from rdpy.layer.gcc import GCCClientConnectionLayer
from rdpy.layer.mcs import MCSLayer, MCSClientConnectionLayer
from rdpy.layer.raw import RawLayer
from rdpy.layer.rdp.connection import RDPClientConnectionLayer
from rdpy.layer.rdp.data import RDPDataLayer
from rdpy.layer.rdp.licensing import RDPLicensingLayer
from rdpy.layer.rdp.security import createNonTLSSecurityLayer, TLSSecurityLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer, createFastPathParser
from rdpy.layer.x224 import X224Layer
from rdpy.mcs.channel import MCSChannelFactory, MCSClientChannel, MCSServerChannel
from rdpy.mcs.client import MCSClientRouter
from rdpy.mcs.user import MCSUserObserver
from rdpy.mitm.observer import MITMSlowPathObserver, MITMFastPathObserver, MITMVirtualChannelObserver
from rdpy.parser.rdp.fastpath import RDPBasicFastPathParser
from rdpy.parser.rdp.negotiation import RDPNegotiationResponseParser, RDPNegotiationRequestParser
from rdpy.protocol.rdp.x224 import ClientTLSContext

from rdpy.pdu.gcc import GCCConferenceCreateResponsePDU
from rdpy.recording.recorder import Recorder, FileLayer, SocketLayer


class MITMClient(MCSChannelFactory, MCSUserObserver):
    def __init__(self, server, fileHandle, socket):
        """
        :type server: rdpy.mitm.server.MITMServer
        :type fileHandle: file
        :type socket: socket.socket
        """
        self.mitm_log = logging.getLogger("mitm.client")
        MCSChannelFactory.__init__(self)
        self.server = server
        record_layers = [FileLayer(fileHandle)]
        if socket is not None:
            record_layers.append(SocketLayer(socket))
        self.recorder = Recorder(record_layers, RDPBasicFastPathParser(ParserMode.SERVER))

        self.tcp = TCPLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()
        self.mcs = MCSLayer()
        self.router = MCSClientRouter(self.mcs, self)
        self.io = RDPDataLayer()
        self.channelMap = {}
        self.channelDefinitions = []
        self.channelObservers = {}
        self.useTLS = False
        self.user = None
        self.securityLayer = None
        self.fastPathParser = None
        self.fastPathObserver = None
        self.licensingLayer = None
        self.conferenceCreateResponse = None
        self.serverData = None
        self.crypter = RC4CrypterProxy()
        self.securitySettings = SecuritySettings(SecuritySettings.Mode.CLIENT)
        self.securitySettings.setObserver(self.crypter)

        self.mcsConnect = MCSClientConnectionLayer(self.mcs)
        self.gccConnect = GCCClientConnectionLayer("1")
        self.rdpConnect = RDPClientConnectionLayer()

        self.tcp.setNext(self.tpkt)
        self.tpkt.setNext(self.x224)
        self.x224.setNext(self.mcs)

        self.mcsConnect.setNext(self.gccConnect)
        self.gccConnect.setNext(self.rdpConnect)

        self.mcs.setObserver(self.router)

        self.tcp.createObserver(onConnection=self.startConnection, onDisconnection=self.onDisconnection)
        self.tpkt.createObserver(onUnknownHeader=self.onUnknownTPKTHeader)
        self.x224.createObserver(onConnectionConfirm=self.onConnectionConfirm, onDisconnectRequest=self.onDisconnectRequest)
        self.router.createObserver(onConnectResponse=self.onConnectResponse, onDisconnectProviderUltimatum=self.onDisconnectProviderUltimatum)
        self.gccConnect.createObserver(onPDUReceived=self.onConferenceCreateResponse)
        self.rdpConnect.createObserver(onPDUReceived=self.onServerData)

    def getProtocol(self):
        return self.tcp

    def startConnection(self):
        """
        Start the connection sequence to the target machine.
        """
        self.mitm_log.debug("TCP connected")
        negotiation = self.server.getNegotiationPDU()
        parser = RDPNegotiationRequestParser()
        self.x224.sendConnectionRequest(parser.write(negotiation))

    def onDisconnection(self, reason):
        self.mitm_log.debug("Connection closed")
        self.server.disconnect()

    def onDisconnectRequest(self, pdu):
        self.mitm_log.debug("X224 Disconnect Request received")
        self.disconnect()

    def disconnect(self):
        self.mitm_log.debug("Disconnecting")
        self.tcp.disconnect()

    def onUnknownTPKTHeader(self, header):
        self.mitm_log.error("Closing the connection because an unknown TPKT header was received. Header: 0x%02lx" % header)
        self.disconnect()

    def onConnectionConfirm(self, pdu):
        """
        Called when the X224 layer is connected.
        """
        self.mitm_log.debug("Connection Confirm received")

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
        self.mitm_log.debug("Sending Connect Initial")

        if clientData.networkData:
            self.channelDefinitions = clientData.networkData.channelDefinitions

        self.gccConnect.conferenceName = gccConferenceCreateRequest.conferenceName
        self.rdpConnect.send(clientData)

    def onConnectResponse(self, pdu):
        """
        Called when an MCS Connect Response PDU is received.
        """
        if pdu.result != 0:
            self.mitm_log.error("MCS Connection Failed")
            self.server.onConnectResponse(pdu, None)
        else:
            self.mitm_log.debug("MCS Connection Successful")
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
        self.user.setObserver(self)
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
        self.mitm_log.debug("building channel {} for user {}".format(channelLog, userID))

        if channelName == "I/O":
            channel = self.buildIOChannel(mcs, userID, channelID)
        else:
            channel = self.buildVirtualChannel(mcs, userID, channelID)

        self.server.onChannelJoinAccepted(userID, channelID)
        return channel

    def createSecurityLayer(self):
        encryptionMethod = self.serverData.security.encryptionMethod

        if self.useTLS:
            return TLSSecurityLayer()
        else:
            return createNonTLSSecurityLayer(encryptionMethod, self.crypter)

    def buildVirtualChannel(self, mcs, userID, channelID):
        channel = MCSClientChannel(mcs, userID, channelID)
        securityLayer = self.createSecurityLayer()
        rawLayer = RawLayer()

        channel.setNext(securityLayer)
        securityLayer.setNext(rawLayer)

        observer = MITMVirtualChannelObserver(rawLayer)
        rawLayer.setObserver(observer)
        self.channelObservers[channelID] = observer

        return channel

    def buildIOChannel(self, mcs, userID, channelID):
        encryptionMethod = self.serverData.security.encryptionMethod
        self.securityLayer = self.createSecurityLayer()

        self.fastPathParser = createFastPathParser(self.useTLS, encryptionMethod, self.crypter, ParserMode.CLIENT)
        self.licensingLayer = RDPLicensingLayer()
        channel = MCSClientChannel(mcs, userID, channelID)

        channel.setNext(self.securityLayer)
        self.securityLayer.setLicensingLayer(self.licensingLayer)
        self.securityLayer.setNext(self.io)
        self.tpkt.setFastPathParser(self.fastPathParser)

        slowPathObserver = MITMSlowPathObserver(self.io, self.recorder, ParserMode.CLIENT)
        self.fastPathObserver = MITMFastPathObserver(self.tpkt, self.recorder, ParserMode.CLIENT)
        self.io.setObserver(slowPathObserver)
        self.tpkt.setObserver(self.fastPathObserver)
        self.licensingLayer.createObserver(onPDUReceived=self.onLicensingPDU)

        self.channelObservers[channelID] = slowPathObserver

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = True
        elif encryptionMethod != 0:
            self.mitm_log.debug("Sending Security Exchange")
            self.io.previous.sendSecurityExchange(self.securitySettings.encryptClientRandom())

        return channel

    def onChannelJoinRefused(self, user, result, channelID):
        self.server.onChannelJoinRefused(user, result, channelID)

    def onClientInfoReceived(self, pdu):
        self.mitm_log.debug("Sending Client Info")

        self.securityLayer.sendClientInfo(pdu)

    def onLicensingPDU(self, pdu):
        self.mitm_log.debug("Licensing PDU received")

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = False

        self.server.onLicensingPDU(pdu)

    def onDisconnectProviderUltimatum(self, pdu):
        self.mitm_log.debug("Disconnect Provider Ultimatum received")
        self.server.sendDisconnectProviderUltimatum(pdu)

    def getChannelObserver(self, channelID):
        return self.channelObservers[channelID]

    def getFastPathObserver(self):
        return self.fastPathObserver
