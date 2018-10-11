from rdpy.core.newlayer import Layer
from rdpy.core.subject import ObservedBy
from rdpy.enum.x224 import X224Header
from rdpy.parser.x224 import X224Parser
from rdpy.pdu.x224 import X224Data, X224ConnectionRequest, X224ConnectionConfirm, X224DisconnectRequest, X224Error
from rdpy.protocol.x224.layer import X224Observer


@ObservedBy(X224Observer)
class X224Layer(Layer):
    """
    Layer for handling X224 related traffic
    ObservedBy: X224Observer
    """

    def __init__(self):
        Layer.__init__(self)
        self.parser = X224Parser()
        self.handlers = {}

    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, pdu.header == X224Header.X224_TPDU_DATA)

    def send(self, payload, **kwargs):
        roa = kwargs.pop("roa", False)
        eot = kwargs.pop("eot", True)

        pdu = X224Data(roa, eot, payload)
        self.previous.send(self.parser.write(pdu))

    def sendConnectionPDU(self, factory, payload, **kwargs):
        credit = kwargs.pop("credit", 0)
        destination = kwargs.pop("destination", 0)
        source = kwargs.pop("source", 0)
        options = kwargs.pop("options", 0)

        pdu = factory(credit, destination, source, options, payload)
        self.previous.send(self.parser.write(pdu))

    def sendConnectionRequest(self, payload, **kwargs):
        self.sendConnectionPDU(X224ConnectionRequest, payload, **kwargs)

    def sendConnectionConfirm(self, payload, **kwargs):
        self.sendConnectionPDU(X224ConnectionConfirm, payload, **kwargs)

    def sendDisconnectRequest(self, reason, **kwargs):
        destination = kwargs.pop("destination", 0)
        source = kwargs.pop("source", 0)
        payload = kwargs.pop("payload", "")

        pdu = X224DisconnectRequest(destination, source, reason, payload)
        self.previous.send(self.parser.write(pdu))

    def sendError(self, cause, **kwargs):
        destination = kwargs.pop("destination", 0)

        pdu = X224Error(destination, cause)
        self.previous.send(self.parser.write(pdu))