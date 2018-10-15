from rdpy.core.newlayer import Layer
from rdpy.parser.rdp import RDPLicensingParser


class RDPLicensingLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.parser = RDPLicensingParser()

    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, False)