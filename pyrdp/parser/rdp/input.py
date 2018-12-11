from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE
from pyrdp.enum import InputEventType
from pyrdp.exceptions import ParsingError, WritingError
from pyrdp.parser.parser import Parser
from pyrdp.pdu import ExtendedMouseEvent, KeyboardEvent, MouseEvent, SynchronizeEvent, UnicodeKeyboardEvent, UnusedEvent


class SlowPathInputParser(Parser):
    def __init__(self):
        super().__init__()
        self.parsers = {
            InputEventType.INPUT_EVENT_SYNC: self.parseSynchronizeEvent,
            InputEventType.INPUT_EVENT_UNUSED: self.parseUnusedEvent,
            InputEventType.INPUT_EVENT_SCANCODE: self.parseKeyboardEvent,
            InputEventType.INPUT_EVENT_UNICODE: self.parseUnicodeKeyboardEvent,
            InputEventType.INPUT_EVENT_MOUSE: self.parseMouseEvent,
            InputEventType.INPUT_EVENT_MOUSEX: self.parseExtendedMouseEvent,
        }

        self.writers = {
            InputEventType.INPUT_EVENT_SYNC: self.writeSynchronizeEvent,
            InputEventType.INPUT_EVENT_UNUSED: self.writeUnusedEvent,
            InputEventType.INPUT_EVENT_SCANCODE: self.writeKeyboardEvent,
            InputEventType.INPUT_EVENT_UNICODE: self.writeUnicodeKeyboardEvent,
            InputEventType.INPUT_EVENT_MOUSE: self.writeMouseEvent,
            InputEventType.INPUT_EVENT_MOUSEX: self.writeExtendedMouseEvent,
        }

    def parse(self, stream):
        eventTime = Uint32LE.unpack(stream)
        messageType = Uint16LE.unpack(stream)

        if messageType not in self.parsers:
            raise ParsingError("Invalid input message type")

        return self.parsers[messageType](stream, eventTime)

    def write(self, input):
        stream = BytesIO()
        Uint32LE.pack(input.eventTime, stream)
        Uint16LE.pack(input.messageType, stream)

        if input.messageType not in self.writers:
            raise WritingError("Invalid input message type")

        self.writers[input.messageType](stream, input)
        return stream.getvalue()

    def parseSynchronizeEvent(self, stream, eventTime):
        stream.read(2)
        flags = Uint32LE.unpack(stream)
        return SynchronizeEvent(eventTime, flags)

    def writeSynchronizeEvent(self, stream, event):
        stream.write(b"\x00" * 2)
        Uint32LE.pack(event.flags, stream)

    def parseUnusedEvent(self, stream, eventTime):
        stream.read(6)
        return UnusedEvent(eventTime)

    def writeUnusedEvent(self, stream, _):
        stream.write(b"\x00" * 6)

    def parseKeyboardEvent(self, stream, eventTime):
        flags = Uint16LE.unpack(stream)
        keyCode = Uint16LE.unpack(stream)
        stream.read(2)
        return KeyboardEvent(eventTime, flags, keyCode)

    def writeKeyboardEvent(self, stream, event):
        Uint16LE.pack(event.flags, stream)
        Uint16LE.pack(event.keyCode, stream)
        stream.write(b"\x00" * 2)

    def parseUnicodeKeyboardEvent(self, stream, eventTime):
        event = self.parseKeyboardEvent(stream, eventTime)
        return UnicodeKeyboardEvent(eventTime, event.flags, event.keyCode)

    def writeUnicodeKeyboardEvent(self, stream, event):
        self.writeKeyboardEvent(stream, event)

    def parseMouseEvent(self, stream, eventTime):
        flags = Uint16LE.unpack(stream)
        x = Uint16LE.unpack(stream)
        y = Uint16LE.unpack(stream)
        return MouseEvent(eventTime, flags, x, y)

    def writeMouseEvent(self, stream, event):
        Uint16LE.pack(event.flags, stream)
        Uint16LE.pack(event.x, stream)
        Uint16LE.pack(event.y, stream)

    def parseExtendedMouseEvent(self, stream, eventTime):
        event = self.parseMouseEvent(stream, eventTime)
        return ExtendedMouseEvent(eventTime, event.flags, event.x, event.y)

    def writeExtendedMouseEvent(self, stream, event):
        self.writeMouseEvent(stream, event)
