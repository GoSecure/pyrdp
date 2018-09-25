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
        version = Uint8.read(data[0 : 1])
        padding = Uint8.read(data[1 : 2])
        length = Uint16BE.read(data[2 : 4])
        payload = data[4 : length]

        if len(payload) != length - 4:
            raise Exception("Payload is too short for TPKT length field")
        
        return TPKTPDU(version, payload)
    
    def write(self, pdu):
        stream = StringIO()
        stream.write(Uint8.write(pdu.version))
        stream.write(Uint8.write(pdu.padding))
        stream.write(Uint16BE.write(pdu.length))
        stream.write(pdu.payload)
        
        return stream.getvalue()