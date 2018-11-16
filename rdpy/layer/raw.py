from rdpy.core.newlayer import Layer
from rdpy.pdu.base_pdu import PDU


class RawLayer(Layer):
    """
    Layer that does nothing with the data beside passing it through the good place.
    """

    def recv(self, data):
        pdu = PDU(data)
        self.pduReceived(pdu, True)

    def send(self, data):
        self.previous.send(data)