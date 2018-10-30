from rdpy.core import log
from rdpy.core.crypto import SecuritySettings
from rdpy.enum.rdp import RDPFastPathParserMode
from rdpy.layer.gcc import GCCClientConnectionLayer
from rdpy.layer.mcs import MCSLayer, MCSClientConnectionLayer
from rdpy.layer.rdp.connection import RDPClientConnectionLayer
from rdpy.layer.rdp.data import RDPDataLayer
from rdpy.layer.rdp.licensing import RDPLicensingLayer
from rdpy.layer.rdp.security import createNonTLSSecurityLayer, TLSSecurityLayer
from rdpy.layer.tcp import TCPLayer
from rdpy.layer.tpkt import TPKTLayer, createFastPathParser
from rdpy.layer.x224 import X224Layer
from rdpy.mcs.channel import MCSChannelFactory, MCSClientChannel
from rdpy.mcs.client import MCSClientRouter
from rdpy.mcs.user import MCSUserObserver
from rdpy.mitm.observer import MITMSlowPathObserver, MITMFastPathObserver
from rdpy.parser.rdp.negotiation import RDPNegotiationParser
from rdpy.protocol.rdp.x224 import ClientTLSContext


class MITMClient(MCSChannelFactory, MCSUserObserver):
    def __init__(self, server):
        MCSChannelFactory.__init__(self)
        self.server = server

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
        self.securitySettings = SecuritySettings(SecuritySettings.Mode.CLIENT)
        self.securityLayer = None
        self.fastPathParser = None
        self.fastPathObserver = None
        self.licensingLayer = None
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

        self.tcp.createObserver(onConnection=self.startConnection, onDisconnection=self.onDisconnection)
        self.x224.createObserver(onConnectionConfirm=self.onConnectionConfirm)
        self.router.createObserver(onConnectResponse=self.onConnectResponse, onDisconnectProviderUltimatum=self.onDisconnectProviderUltimatum)
        self.gccConnect.createObserver(onPDUReceived=self.onConferenceCreateResponse)
        self.rdpConnect.createObserver(onPDUReceived=self.onServerData)

    def getProtocol(self):
        return self.tcp

    def logSSLParameters(self):
        log.get_ssl_logger().info(self.tpkt.previous.transport.protocol._tlsConnection.client_random(),
                                  self.tpkt.previous.transport.protocol._tlsConnection.master_key())

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

    def onDisconnection(self, reason):
        self.log_debug("Connection closed")
        self.server.disconnect()

    def disconnect(self):
        self.log_debug("Disconnecting")
        self.tcp.disconnect()

    def onConnectionConfirm(self, pdu):
        """
        Called when the X224 layer is connected.
        """
        self.log_debug("Connection Confirm received")

        negotiation = self.server.getNegotiationPDU()
        if negotiation.tlsSupported:
            self.tcp.startTLS(ClientTLSContext())
            self.useTLS = True

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
        if self.useTLS:
            self.logSSLParameters()

        if pdu.result != 0:
            log.error("MCS Connection Failed")
            self.server.onConnectResponse(pdu, None)
        else:
            self.log_debug("MCS Connection Successful")
            self.mcsConnect.recv(pdu)
            self.server.onConnectResponse(pdu, self.serverData)

    def onConferenceCreateResponse(self, pdu):
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

    # MCS Attach User Confirm successful
    def onAttachConfirmed(self, user):
        self.server.onAttachConfirmed(user)

    # MCS Attach User Confirm failed
    def onAttachRefused(self, user, result):
        self.server.onAttachRefused(user, result)

    def onChannelJoinRequest(self, pdu):
        self.mcs.send(pdu)

    def buildChannel(self, mcs, userID, channelID):
        self.log_debug("building channel {} for user {}".format(channelID, userID))

        if channelID != userID and self.channelMap[channelID] == "I/O":
            encryptionMethod = self.serverData.security.encryptionMethod

            if self.useTLS:
                crypter = None
                self.securityLayer = TLSSecurityLayer()
            else:
                crypter = self.securitySettings.getCrypter()
                self.securityLayer = createNonTLSSecurityLayer(encryptionMethod, crypter)

            self.fastPathParser = createFastPathParser(self.useTLS, encryptionMethod, crypter, RDPFastPathParserMode.CLIENT)
            self.licensingLayer = RDPLicensingLayer()
            channel = MCSClientChannel(mcs, userID, channelID)

            channel.setNext(self.securityLayer)
            self.securityLayer.setLicensingLayer(self.licensingLayer)
            self.securityLayer.setNext(self.io)
            self.tpkt.setFastPathParser(self.fastPathParser)

            slowPathObserver = MITMSlowPathObserver(self.io, "Client")
            self.fastPathObserver = MITMFastPathObserver(self.tpkt, "Client")
            self.io.setObserver(slowPathObserver)
            self.tpkt.setObserver(self.fastPathObserver)
            self.licensingLayer.createObserver(onPDUReceived=self.onLicensingPDU)

            self.channelObservers[channelID] = slowPathObserver

            if self.useTLS:
                self.securityLayer.securityHeaderExpected = True
            elif encryptionMethod != 0:
                self.log_debug("Sending Security Exchange")
                self.io.previous.sendSecurityExchange(self.securitySettings.encryptClientRandom())
        else:
            channel = None

        self.server.onChannelJoinAccepted(userID, channelID)
        return channel

    def onChannelJoinRefused(self, user, result, channelID):
        self.server.onChannelJoinRefused(user, result, channelID)

    def onClientInfoReceived(self, pdu):
        self.log_debug("Sending Client Info")

        self.securityLayer.sendClientInfo(pdu)

    def onLicensingPDU(self, pdu):
        self.log_debug("Licensing PDU received")

        if self.useTLS:
            self.securityLayer.securityHeaderExpected = False

        self.server.onLicensingPDU(pdu)

    def onDisconnectProviderUltimatum(self, pdu):
        self.log_debug("Disconnect Provider Ultimatum received")
        self.server.sendDisconnectProviderUltimatum(pdu)

    def getChannelObserver(self, channelID):
        return self.channelObservers[channelID]

    def getFastPathObserver(self):
        return self.fastPathObserver