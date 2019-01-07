from collections import OrderedDict

from twisted.internet.protocol import ClientFactory

from pyrdp.enum import EncryptionMethod, NegotiationProtocols
from pyrdp.logging import log
from pyrdp.mcs import MCSChannel, MCSChannelFactory
from pyrdp.pdu.rdp.connection import ClientDataPDU
from pyrdp.scripting.layerset import RDPClientLayerSet


class RDPClient(ClientFactory, MCSChannelFactory):
    def __init__(self):
        self.selectedProtocols: NegotiationProtocols = None
        self.layers = RDPClientLayerSet(self)
        self.slowPathID: int = None
        self.channels = OrderedDict()

    def buildChannel(self, mcs, userID, channelID):
        channel = MCSChannel(mcs, userID, channelID)
        return channel

    async def connect(self, host: str, port: int, username: str, password: str):
        await self.layers.connectTCP(host, port)

        if not await self.layers.connectX224(username):
            raise RuntimeError(f"Failed to connect to {host}:{port}")

        clientData = ClientDataPDU.generate(self.layers.x224Protocols, encryptionMethods = EncryptionMethod.ENCRYPTION_128BIT, drive = True, clipboard = True, sound = True)
        await self.layers.connectMCS(clientData)

        log.info(f"Connected!")