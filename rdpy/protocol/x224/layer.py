from abc import abstractmethod

from rdpy.core import log
from pdu import X224Parser, X224Data, X224Header, X224ConnectionRequest

class X224Layer:
    """
    @summary: Layer for handling X224 related traffic
    """

    def __init__(self):
        self.previous = None
        self.next = None
        self.parser = X224Parser()
    
    def recv(self, data):
        pdu = self.parser.parse(data)

        if pdu.header == X224Header.X224_TPDU_DATA:
            self.next.recv(pdu.payload)
        else:
            self.recvPDU(pdu)

    @abstractmethod
    def recvPDU(pdu):
        pass    
    
    def send(self, data):
        pdu = X224Data(False, True, data)
        self.previous.send(self.parser.write(pdu))
    
class X224ClientLayer:
    """
    @summary: Layer for client-side X224 traffic
    """

    def __init__(self):
        super(X224Layer, self).__init__()
        self.connecting = False
        self.connected = False
    
    def recvPDU(self, pdu):
        if pdu.header == X224Header.X224_TPDU_CONNECTION_CONFIRM:
            if self.connecting:
                self.connected = True
            else:
                log.warning("Received a Connection Confirm PDU without sending a Connection Request")
        elif pdu.header == X224Header.X224_TPDU_DISCONNECT_REQUEST:
            self.connected = False
            log.warning("Received disconnect request")
        elif pdu.header == X224Header.X224_TPDU_ERROR:
            log.error("Received error PDU, cause: 0x%lx" % pdu.cause)
        else:
            log.error("Unhandled PDU received")
        
        self.connecting = False
    
    def send(self, data):
        if not self.connected:
            raise Exception("Cannot send data when not connected")
        
        super(X224Layer, self).send(data)

    def sendConnectionRequest(self, payload):
        pdu = X224ConnectionRequest(0, 0, 0, 0 payload)
        self.previous.send(self.parser.write(pdu))
        self.connecting = True