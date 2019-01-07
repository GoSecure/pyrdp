import asyncio
from collections import OrderedDict
from typing import Optional

from pyrdp.parser import GCCParser
from pyrdp.parser.rdp.connection import ClientConnectionParser, ServerConnectionParser
from pyrdp.pdu.rdp.connection import ClientDataPDU

from pyrdp.core.ssl import ClientTLSContext

from pyrdp.enum import NegotiationProtocols, NegotiationRequestFlags, SegmentationPDUType
from pyrdp.layer import Layer, MCSLayer, TPKTLayer, TwistedTCPLayer, X224Layer
from pyrdp.layer.rdp.fastpath import FastPathLayer
from pyrdp.layer.rdp.security import SecurityLayer
from pyrdp.layer.rdp.slowpath import SlowPathLayer
from pyrdp.layer.segmentation import SegmentationLayer
from pyrdp.mcs import MCSChannelFactory, MCSRouter, MCSServerRouter
from pyrdp.mcs.client import MCSClientRouter
from pyrdp.parser.rdp.negotiation import NegotiationRequestParser, NegotiationResponseParser
from pyrdp.pdu import X224ConnectionConfirmPDU, GCCConferenceCreateRequestPDU, MCSConnectResponsePDU, \
    MCSErectDomainRequestPDU, MCSAttachUserConfirmPDU
from pyrdp.pdu.rdp.negotiation import NegotiationRequestPDU


class RDPLayerSet:
    """
    Class that handles initialization of regular RDP layers.
    """
    def __init__(self, router: MCSRouter):
        """
        :param router: the MCS router to use. The MCS layer used is the router's MCS layer.
        """
        self.tcp = TwistedTCPLayer()
        self.segmentation = SegmentationLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()
        self.mcs = router.mcs
        self.router = router
        self.security: SecurityLayer = None
        self.slowPath = SlowPathLayer()
        self.fastPath: FastPathLayer = None

        self.mcs.addObserver(self.router)

        self.tcp.setNext(self.segmentation)
        self.segmentation.attachLayer(SegmentationPDUType.TPKT, self.tpkt)
        Layer.chain(self.tpkt, self.x224, self.mcs)

    @staticmethod
    def createClient(factory: MCSChannelFactory):
        mcs = MCSLayer()
        router = MCSClientRouter(mcs, factory)
        return RDPLayerSet(router)

    @staticmethod
    def createServer(factory: MCSChannelFactory):
        mcs = MCSLayer()
        router = MCSServerRouter(mcs, factory)
        return RDPLayerSet(router)


class RDPClientLayerSet(RDPLayerSet):
    """
    Class that handles layers on the RDP client side.
    """

    def __init__(self, factory: MCSChannelFactory):
        """
        :param factory: The factory to call for creating MCS channels.
        """
        mcs = MCSLayer()
        router = MCSClientRouter(mcs, factory)
        super().__init__(router)

        self.x224Protocols: Optional[NegotiationProtocols] = None
        self.mcsUser = router.createUser()
        self.slowPathChannelID: Optional[int] = None
        self.channels = OrderedDict()

    async def connectTCP(self, host: str, port: int, timeout: Optional[float] = 10.0):
        """
        Connect to host:port via TCP. If timeout is None, the future will wait until connection succeeds.
        :param host: the host IP to connect to.
        :param port: the port to connect to.
        :param timeout: time to wait for a connection to be established.
        :return: False if the timeout was reached, otherwise True.
        """
        from twisted.internet import reactor
        from twisted.internet.protocol import ClientFactory

        class Factory(ClientFactory):
            def buildProtocol(_, addr):
                return self.tcp

        reactor.connectTCP(host, port, Factory())

        try:
            await asyncio.wait_for(self.tcp.connectedEvent.wait(), timeout)
        except asyncio.TimeoutError:
            return False

        return True

    async def connectX224(self, mstshash: str, protocols: NegotiationProtocols = NegotiationProtocols.SSL, tlsContext = ClientTLSContext()):
        """
        Connect the X224 layer. This will populate the x224Protocols variable with the selected protocols.
        :param mstshash: the mstshash cookie value.
        :param protocols: negotiation protocols supported.
        :param tlsContext: TLS context to use if TLS is selected.
        :return: True if connection was successful.
        """
        if protocols & NegotiationProtocols.CRED_SSP != 0:
            raise ValueError("CredSSP is not supported")

        if protocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0:
            raise ValueError("Early authorization is not supported")

        pdu = NegotiationRequestPDU(f"Cookie: mstshash={mstshash}".encode(), NegotiationRequestFlags.NONE, protocols)
        payload = NegotiationRequestParser().write(pdu)

        self.x224.sendConnectionRequest(payload)

        pdu = await self.x224.waitPDU(where={"__class__": X224ConnectionConfirmPDU})
        pdu = NegotiationResponseParser().parse(pdu.payload)

        if pdu.selectedProtocols is None:
            return False

        if pdu.selectedProtocols & NegotiationProtocols.SSL != 0:
            self.tcp.startTLS(tlsContext)

        self.x224Protocols = pdu.selectedProtocols
        return self.x224Protocols is not None

    async def connectMCS(self, clientData: ClientDataPDU):
        pdu = GCCConferenceCreateRequestPDU("1", ClientConnectionParser().write(clientData))
        self.mcs.sendConnectInitial(GCCParser().write(pdu))

        pdu = await self.mcs.waitPDU(match=lambda response: isinstance(response, MCSConnectResponsePDU))

        pdu = GCCParser().parse(pdu.payload)
        pdu = ServerConnectionParser().parse(pdu.payload)
        self.slowPathChannelID = pdu.network.mcsChannelID

        for channelDef in clientData.networkData.channelDefinitions:
            self.channels[channelDef.name] = None

        channelNames = list(self.channels.keys())
        for i in range(len(pdu.network.channels)):
            self.channels[channelNames[i]] = pdu.network.channels[i]

        self.mcs.sendPDU(MCSErectDomainRequestPDU(1, 1, b""))
        self.mcsUser.attach()

        await self.mcs.waitPDU(match=lambda response: isinstance(response, MCSAttachUserConfirmPDU))

        self.mcsUser.joinChannel(self.mcsUser.userID)
        self.mcsUser.joinChannel(self.slowPathChannelID)

        for channel in self.channels.values():
            self.mcsUser.joinChannel(channel)