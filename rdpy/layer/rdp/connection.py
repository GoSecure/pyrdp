from rdpy.layer.layer import Layer
from rdpy.parser.rdp.connection import RDPClientConnectionParser, RDPServerConnectionParser


class RDPClientConnectionLayer(Layer):
    """
    Layer for client RDP connection data. Sends Client PDUs and receives Server PDUs.
    """
    def __init__(self):
        Layer.__init__(self, None, hasNext=True)
        self.clientRDP = RDPClientConnectionParser()
        self.serverRDP = RDPServerConnectionParser()

    def recv(self, data):
        pdu = self.serverRDP.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, pdu):
        self.previous.send(self.clientRDP.write(pdu))
