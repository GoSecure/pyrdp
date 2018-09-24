from StringIO import StringIO

from pdu import TPKTParser, TPKTPDU
from rdpy.core.type import StringStream

class TPKTLayer:
    """
    @summary: Layer for handling TPKT-wrapped traffic
    """

    def __init__(self):
        self.previous = None
        self.next = None
        self.parser = TPKTParser()
    
    def recv(self, data):
        pdu = self.parser.parse(data)

        if self.next is not None:
            self.next.dataReceived(pdu.payload)
    
    def send(self, data):
        pdu = TPKTPDU(3, len(data), data)
        self.previous.send(self.parser.write(pdu))