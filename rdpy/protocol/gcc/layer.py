from rdpy.core.layer import Layer
from pdu import GCCParser, GCCPDUType

class GCCLayerMode:
    CLIENT = 0
    SERVER = 1

class GCCLayer(Layer):
    def __init__(self, mode):
        super(GCCLayer, self).__init__()
        self.parser = GCCParser()
        
        if mode == GCCLayerMode.CLIENT:
            self.recvHeader = GCCPDUType.CREATE_CONFERENCE_RESPONSE
            self.sendHeader = GCCPDUType.CREATE_CONFERENCE_REQUEST
        else:
            self.recvHeader = GCCPDUType.CREATE_CONFERENCE_REQUEST
            self.sendHeader = GCCPDUType.CREATE_CONFERENCE_RESPONSE
    
    def recv(self, data):
        pdu = self.parser.parse(data)

        if pdu.header != self.recvHeader:
            raise Exception("Invalid GCC PDU type received")
        
        self.next.recv(pdu.payload)
    
    def send(self, pdu):
        if pdu.header != self.sendHeader:
            raise Exception("Trying to send invalid GCC PDU type")

        self.previous.send(self.parser.write(pdu))