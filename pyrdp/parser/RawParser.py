from pyrdp.parser import Parser
from pyrdp.pdu import PDU


class RawParser(Parser):
    def parse(self, data: bytes) -> PDU:
        return PDU(data)

    def write(self, pdu: PDU) -> bytes:
        return pdu.payload