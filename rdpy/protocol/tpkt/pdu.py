from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16BE

class TPKTPDU:
    """
    @summary: TPKT PDU definition
    """

    def __init__(self, version, payload):
        self.version = version
        self.padding = 0
        self.length = len(payload) + 4
        self.payload = payload

class TPKTParser:
    """
    @summary: Parser for TPKT traffic
    """

    def parse(self, data):
        version = Uint8.read(self.data[0 : 1])
        padding = Uint8.read(self.data[1 : 2])
        length = Uint16BE.read(self.data[2 : 4])
        payload = self.data[4 :]

        if len(payload) + 4 != length:
            raise Exception("TPKT length field does not match payload length")
        
        return TPKTPDU(version, payload)
    
    def write(self, pdu):
        stream = StringIO()
        stream.write(Uint8.write(pdu.version))
        stream.write(Uint8.write(pdu.padding))
        stream.write(Uint16BE.write(pdu.length))
        stream.write(pdu.payload)
        
        return stream.getvalue()