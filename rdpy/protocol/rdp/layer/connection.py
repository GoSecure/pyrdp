from rdpy.core.newlayer import Layer
from rdpy.protocol.rdp.pdu.connection import RDPClientConnectionParser, RDPServerConnectionParser

class RDPClientConnectionLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.clientRDP = RDPClientConnectionParser()
        self.serverRDP = RDPServerConnectionParser()
    
    def recv(self, data):
        pdu = self.serverRDP.parse(data)
        self.pduReceived(pdu, True)
    
    def send(self, pdu):
        self.previous.send(self.clientRDP.write(pdu))