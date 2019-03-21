from io import BytesIO

from pyrdp.core import Uint16LE, Uint64LE
from pyrdp.enum import PlayerPDUType
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.pdu import PlayerPDU


class PlayerParser(SegmentationParser):
    def parse(self, data: bytes) -> PlayerPDU:
        stream = BytesIO(data)

        length = Uint64LE.unpack(stream)
        type = PlayerPDUType(Uint16LE.unpack(stream))
        timestamp = Uint64LE.unpack(stream)
        payload = stream.read(length - 18)

        return PlayerPDU(type, timestamp, payload)

    def write(self, pdu: PlayerPDU) -> bytes:
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