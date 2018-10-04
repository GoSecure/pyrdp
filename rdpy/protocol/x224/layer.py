from rdpy.core import log
from rdpy.core.newlayer import Layer, LayerStrictRoutedObserver
from rdpy.core.subject import Subject
from pdu import X224Parser, X224Data, X224Header, X224ConnectionRequest, X224ConnectionConfirm, X224DisconnectRequest

class X224Observer(LayerStrictRoutedObserver):
    def __init__(self):
        LayerStrictRoutedObserver.__init__(self, {
            X224Header.X224_TPDU_CONNECTION_REQUEST: self.connectionRequest,
            X224Header.X224_TPDU_CONNECTION_CONFIRM: self.connectionConfirm,
            X224Header.X224_TPDU_DISCONNECT_REQUEST: self.disconnectRequest,
            X224Header.X224_TPDU_DATA: self.x224Data,
            X224Header.X224_TPDU_ERROR: self.error
        })

    def connectionRequest(self, pdu):
        raise Exception("Unhandled X224 Connection Request PDU")

    def connectionConfirm(self, pdu):
        raise Exception("Unhandled X224 Connection Confirm PDU")
    
    def disconnectRequest(self, pdu):
        raise Exception("Unhandled X224 Disconnect Request PDU")
    
    def x224Data(self, pdu):
        pass

    def error(self, pdu):
        raise Exception("Unhandled X224 Error PDU")

class X224Layer(Layer, Subject):
    """
    @summary: Layer for handling X224 related traffic
    """

    def __init__(self):
        Layer.__init__(self)
        Subject.__init__(self)
        self.parser = X224Parser()
    
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
