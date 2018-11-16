from rdpy.core.newlayer import Layer
from rdpy.parser.rdp.licensing import RDPLicensingParser


class RDPLicensingLayer(Layer):
    """
    Layer for traffic related to RDP licensing.
    """
    def __init__(self):
        Layer.__init__(self)
        self.parser = RDPLicensingParser()

    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, False)

    def sendPDU(self, pdu):
        data = self.parser.write(pdu)
        self.previous.send(data)