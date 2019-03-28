from io import BytesIO

from pyrdp.core import Int16LE, Uint16LE, Uint64LE, Uint8
from pyrdp.enum import MouseButton, PlayerPDUType
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.pdu import PlayerKeyboardPDU, PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerMouseWheelPDU, PlayerPDU, \
    PlayerTextPDU


class PlayerParser(SegmentationParser):
    def __init__(self):
        super().__init__()

        self.parsers = {
            PlayerPDUType.MOUSE_MOVE: self.parseMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.parseMouseButton,
            PlayerPDUType.MOUSE_WHEEL: self.parseMouseWheel,
            PlayerPDUType.KEYBOARD: self.parseKeyboard,
            PlayerPDUType.TEXT: self.parseText,
        }

        self.writers = {
            PlayerPDUType.MOUSE_MOVE: self.writeMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.writeMouseButton,
            PlayerPDUType.MOUSE_WHEEL: self.writeMouseWheel,
            PlayerPDUType.KEYBOARD: self.writeKeyboard,
            PlayerPDUType.TEXT: self.writeText,
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


    def parseMouseWheel(self, stream: BytesIO, timestamp: int) -> PlayerMouseWheelPDU:
        x, y = self.parseMousePosition(stream)
        delta = Int16LE.unpack(stream)
        horizontal = bool(Uint8.unpack(stream))
        return PlayerMouseWheelPDU(timestamp, x, y, delta, horizontal)

    def writeMouseWheel(self, pdu: PlayerMouseWheelPDU, stream: BytesIO):
        self.writeMousePosition(pdu.x, pdu.y, stream)
        Int16LE.pack(pdu.delta, stream)
        Uint8.pack(int(pdu.horizontal), stream)


    def parseKeyboard(self, stream: BytesIO, timestamp: int) -> PlayerKeyboardPDU:
        code = Uint16LE.unpack(stream)
        released = bool(Uint8.unpack(stream))
        extended = bool(Uint8.unpack(stream))
        return PlayerKeyboardPDU(timestamp, code, released, extended)

    def writeKeyboard(self, pdu: PlayerKeyboardPDU, stream: BytesIO):
        Uint16LE.pack(pdu.code, stream)
        Uint8.pack(int(pdu.released), stream)
        Uint8.pack(int(pdu.extended), stream)


    def parseText(self, stream:  BytesIO, timestamp: int) -> PlayerTextPDU:
        length = Uint8.unpack(stream)
        character = stream.read(length).decode()
        released = Uint8.unpack(stream)
        return PlayerTextPDU(timestamp, character, bool(released))

    def writeText(self, pdu: PlayerTextPDU, stream: BytesIO):
        encoded = pdu.character[: 1].encode()

        Uint8.pack(len(encoded), stream)
        stream.write(encoded)
        Uint8.pack(int(pdu.released), stream)
