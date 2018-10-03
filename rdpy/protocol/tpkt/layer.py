from rdpy.core.newlayer import Layer
from pdu import TPKTParser, TPKTPDU

class TPKTLayer(Layer):
    """
    @summary: Layer for handling TPKT-wrapped traffic
    """

    def __init__(self):
        super(TPKTLayer, self).__init__()
        self.parser = TPKTParser()
    
    def recv(self, data):
        while len(data) > 0:
            pdu = self.parser.parse(data)
            self.next.recv(pdu.payload)
            data = data[pdu.length :]
    
    def send(self, data):
        pdu = TPKTPDU(3, data)
        self.previous.send(self.parser.write(pdu))
