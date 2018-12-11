from pyrdp.layer.layer import Layer
from pyrdp.parser import ClientConnectionParser, ServerConnectionParser


class ClientConnectionLayer(Layer):
    """
    Layer for client RDP connection data. Sends Client PDUs and receives Server PDUs.
    """
    def __init__(self):
        Layer.__init__(self, None, hasNext=True)
        self.clientRDP = ClientConnectionParser()
        self.serverRDP = ServerConnectionParser()

    def recv(self, data):
        pdu = self.serverRDP.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, pdu):
        self.previous.send(self.clientRDP.write(pdu))
