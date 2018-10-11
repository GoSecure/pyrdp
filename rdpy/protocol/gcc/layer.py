from pdu import GCCParser, GCCConferenceCreateRequestPDU
from rdpy.core.newlayer import Layer

class GCCClientConnectionLayer(Layer):
    def __init__(self, conferenceName):
        Layer.__init__(self)
        self.conferenceName = conferenceName
        self.parser = GCCParser()
    
    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, True)

    def send(self, data):
        pdu = GCCConferenceCreateRequestPDU(self.conferenceName, data)
        self.previous.send(self.parser.write(pdu))