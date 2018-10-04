from rdpy.core.newlayer import Layer
from pdu import TPKTParser, TPKTPDU

class TPKTLayer(Layer):
    """
    @summary: Layer for handling TPKT-wrapped traffic
    """

    def __init__(self):
        Layer.__init__(self)
        self.parser = TPKTParser()
    
    def recv(self, data):
        while len(data) > 0:
            pdu = self.parser.parse(data)
            self.pduReceived(pdu, True)
            data = data[pdu.length :]
    
    def send(self, data):
        pdu = TPKTPDU(3, data)
        self.previous.send(self.parser.write(pdu))
