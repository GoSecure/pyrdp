from io import BytesIO

from pyrdp.core import Uint16LE, Uint64LE, Uint8
from pyrdp.enum import PlayerPDUType
from pyrdp.enum.player import MouseButton
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.pdu import PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerPDU


class PlayerParser(SegmentationParser):
    def __init__(self):
        super().__init__()

        self.parsers = {
            PlayerPDUType.MOUSE_MOVE: self.parseMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.parseMouseButton,
        }

        self.writers = {
            PlayerPDUType.MOUSE_MOVE: self.writeMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.writeMouseButton
        }

    def getPDULength(self, data: bytes) -> int:
        return Uint64LE.unpack(data[: 8])

    def isCompletePDU(self, data: bytes) -> bool:
        if len(data) < 8:
            return False

        return len(data) >= self.getPDULength(data)

    def parse(self, data: bytes) -> PlayerPDU:
        stream = BytesIO(data)

        length = Uint64LE.unpack(stream)
        type = PlayerPDUType(Uint16LE.unpack(stream))
        timestamp = Uint64LE.unpack(stream)

        if type in self.parsers:
            return self.parsers[type](stream, timestamp)

        payload = stream.read(length - 18)
        return PlayerPDU(type, timestamp, payload)

    def write(self, pdu: PlayerPDU) -> bytes:
        substream = BytesIO()

        Uint16LE.pack(pdu.header, substream)
        Uint64LE.pack(pdu.timestamp, substream)

        if pdu.header in self.writers:
            self.writers[pdu.header](pdu, substream)

        substream.write(pdu.payload)
        substreamValue = substream.getvalue()

        stream = BytesIO()
        Uint64LE.pack(len(substreamValue) + 8, stream)
        stream.write(substreamValue)

        return stream.getvalue()

    def parseMousePosition(self, stream: BytesIO) -> (int, int):
        x = Uint16LE.unpack(stream)
        y = Uint16LE.unpack(stream)
        return x, y

    def writeMousePosition(self, x: int, y: int, stream: BytesIO):
        Uint16LE.pack(x, stream)
        Uint16LE.pack(y, stream)

    def parseMouseMove(self, stream: BytesIO, timestamp: int) -> PlayerMouseMovePDU:
        x, y = self.parseMousePosition(stream)
        return PlayerMouseMovePDU(timestamp, x, y)

    def writeMouseMove(self, pdu: PlayerMouseMovePDU, stream: BytesIO):
        self.writeMousePosition(pdu.x, pdu.y, stream)

    def parseMouseButton(self, stream: BytesIO, timestamp: int) -> PlayerMouseButtonPDU:
        x, y = self.parseMousePosition(stream)
        button = MouseButton(Uint8.unpack(stream))
        pressed = Uint8.unpack(stream)
        return PlayerMouseButtonPDU(timestamp, x, y, button, bool(pressed))

    def writeMouseButton(self, pdu: PlayerMouseButtonPDU, stream: BytesIO):
        self.writeMousePosition(pdu.x, pdu.y, stream)
        Uint8.pack(pdu.button.value, stream)
        Uint8.pack(int(pdu.pressed), stream)