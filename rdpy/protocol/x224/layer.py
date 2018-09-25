from abc import abstractmethod, ABCMeta

from rdpy.core import log
from pdu import X224Parser, X224Data, X224Header, X224ConnectionRequest, X224ConnectionConfirm, X224DisconnectRequest

class X224Controller:
    __metaclass__ = ABCMeta

    @abstractmethod
    def connectionRequest(self, pdu):
        pass
    
    @abstractmethod
    def connectionConfirm(self, pdu):
        pass
    
    @abstractmethod
    def disconnectRequest(self, pdu):
        pass
    
    @abstractmethod
    def error(self, pdu):
        pass

class X224Layer:
    """
    @summary: Layer for handling X224 related traffic
    """

    def __init__(self, controller):
        self.previous = None
        self.next = None
        self.parser = X224Parser()
        self.controller = controller
        self.handlers = {
            X224Header.X224_TPDU_CONNECTION_REQUEST: self.controller.connectionRequest,
            X224Header.X224_TPDU_CONNECTION_CONFIRM: self.controller.connectionConfirm,
            X224Header.X224_TPDU_DISCONNECT_REQUEST: self.controller.disconnectRequest,
            X224Header.X224_TPDU_ERROR: self.controller.error
        }
    
    def recv(self, data):
        pdu = self.parser.parse(data)

        if pdu.header == X224Header.X224_TPDU_DATA:
            self.next.recv(pdu.payload)
        elif pdu.header in self.handlers:
            self.handlers[pdu.header](pdu)
        else:
            raise Exception("Unhandled PDU received")
    
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
