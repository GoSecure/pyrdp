from rdpy.core.newlayer import Layer
from rdpy.protocol.x224.layer import X224Observer

from pdu import GCCParser, GCCConferenceCreateRequestPDU

class GCCClientConnectionLayer(Layer, X224Observer):
    def __init__(self, conferenceName):
        Layer.__init__(self)
        X224Observer.__init__(self)
        self.conferenceName = conferenceName
        self.parser = GCCParser()
    
    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, True)

    def send(self, data):
        pdu = GCCConferenceCreateRequestPDU(self.conferenceName, data)
        self.previous.send(self.parser.write(pdu))