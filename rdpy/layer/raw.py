from rdpy.core.newlayer import Layer
from rdpy.pdu.base_pdu import PDU


class RawLayer(Layer):
    def recv(self, data):
        pdu = PDU(data)
        self.pduReceived(pdu, True)

    def send(self, data):
        self.previous.send(data)