from rdpy.core.newlayer import Layer

from rdpy.protocol.parser.gcc import GCCParser
from rdpy.protocol.pdu.gcc import GCCConferenceCreateRequestPDU


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