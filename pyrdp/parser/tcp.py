from pyrdp.parser import Parser
from pyrdp.pdu import PDU
from pyrdp.pdu.tcp import TCPPDU


class TCPParser(Parser):
    def parse(self, data: bytes) -> TCPPDU:
        return TCPPDU(data)

    def write(self, pdu: PDU) -> bytes:
        return pdu.payload