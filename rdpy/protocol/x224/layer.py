from pdu import X224Parser, X224Data, X224Header

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
        
    def send(self, data):
        pdu = X224Data(False, True, data)
        self.previous.send(self.parser.write(pdu))