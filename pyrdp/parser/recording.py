from io import BytesIO

from pyrdp.core import Uint16LE, Uint64LE
from pyrdp.enum import PlayerMessageType
from pyrdp.parser import SegmentationParser
from pyrdp.pdu import PlayerMessagePDU


class PlayerMessageParser(SegmentationParser):
    def parse(self, data: bytes) -> PlayerMessagePDU:
        stream = BytesIO(data)

        length = Uint64LE.unpack(stream)
        type = PlayerMessageType(Uint16LE.unpack(stream))
        timestamp = Uint64LE.unpack(stream)
        payload = stream.read(length - 18)

        return PlayerMessagePDU(type, timestamp, payload)

    def write(self, pdu: PlayerMessagePDU) -> bytes:
        stream = BytesIO()

        # 18 bytes of header + the payload
        Uint64LE.pack(len(pdu.payload) + 18, stream)
        Uint16LE.pack(pdu.header, stream)
        Uint64LE.pack(pdu.timestamp, stream)
        stream.write(pdu.payload)

        return stream.getvalue()

    def getPDULength(self, data):
        return Uint64LE.unpack(data[: 8])

    def isCompletePDU(self, data):
        if len(data) < 8:
            return False

        return len(data) >= self.getPDULength(data)