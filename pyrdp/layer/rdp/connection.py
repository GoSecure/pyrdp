from pyrdp.layer.layer import Layer
from pyrdp.parser import ClientConnectionParser, ServerConnectionParser


class ClientConnectionLayer(Layer):
    """
    Layer for client RDP connection data. Sends Client PDUs and receives Server PDUs.
    """
    def __init__(self, sendParser = ClientConnectionParser(), recvParser = ServerConnectionParser()):
        """
        :param sendParser: parser to use when sending client PDUs.
        :param recvParser: parser to use when receiving server PDUs.
        """
        Layer.__init__(self, None, hasNext=True)
        self.sendParser = sendParser
        self.recvParser = recvParser

    def recv(self, data):
        pdu = self.recvParser.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, pdu):
        self.previous.send(self.sendParser.write(pdu))
