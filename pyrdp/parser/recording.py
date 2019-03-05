from io import BytesIO

from pyrdp.core import Uint64LE, Uint8
from pyrdp.enum import PlayerMessageType
from pyrdp.parser import Parser
from pyrdp.pdu.rdp.recording import PlayerMessagePDU


class PlayerMessageParser(Parser):
    def parse(self, data: bytes) -> PlayerMessagePDU:
        stream = BytesIO(data)
        type = PlayerMessageType(Uint8.unpack(stream))
        timestamp = Uint64LE.unpack(stream)
        payload = stream.read()
        return PlayerMessagePDU(type, timestamp, payload)

    def write(self, pdu: PlayerMessagePDU) -> bytes:
        stream = BytesIO()
        Uint8.pack(pdu.header, stream)
        Uint64LE.pack(pdu.timestamp, stream)
        stream.write(pdu.payload)
        return stream.getvalue()