from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE
from pyrdp.enum import PointerEventType
from pyrdp.exceptions import ParsingError
from pyrdp.parser.parser import Parser
from pyrdp.pdu import Point, PointerCacheEvent, PointerColorEvent, PointerNewEvent, PointerPositionEvent, \
    PointerSystemEvent


class PointerEventParser(Parser):
    def __init__(self):
        self.parsers = {
            PointerEventType.TS_PTRMSGTYPE_SYSTEM: self.parseSystemEvent,
            PointerEventType.TS_PTRMSGTYPE_POSITION: self.parsePositionEvent,
            PointerEventType.TS_PTRMSGTYPE_COLOR: self.parseColorEvent,
            PointerEventType.TS_PTRMSGTYPE_CACHED: self.parseCacheEvent,
            PointerEventType.TS_PTRMSGTYPE_POINTER: self.parseNewEvent,
        }

        self.writers = {
            PointerEventType.TS_PTRMSGTYPE_SYSTEM: self.writeSystemEvent,
            PointerEventType.TS_PTRMSGTYPE_POSITION: self.writePositionevent,
            PointerEventType.TS_PTRMSGTYPE_COLOR: self.writeColorEvent,
            PointerEventType.TS_PTRMSGTYPE_CACHED: self.writeCacheEvent,
            PointerEventType.TS_PTRMSGTYPE_POINTER: self.writeNewEvent,
        }

    def parse(self, stream):
        messageType = Uint16LE.unpack(stream)
        stream.read(2)

        if messageType not in self.parsers:
            raise ParsingError("Trying to parse invalid pointer event type")

        return self.parsers[messageType](stream)

    def write(self, event):
        stream = BytesIO()
        Uint16LE.pack(event.messageType, stream)
        stream.write(b"\x00" * 2)

        if event.messageType not in self.writers:
            raise ParsingError("Trying to write invalid pointer event type")

        self.writers[event.messageType](stream, event)
        return stream.getvalue()

    def parseSystemEvent(self, stream):
        pointerType = Uint32LE.unpack(stream)
        return PointerSystemEvent(pointerType)

    def writeSystemEvent(self, stream, event):
        Uint32LE.pack(event.pointerType, stream)

    def parsePositionEvent(self, stream):
        x = Uint16LE.unpack(stream)
        y = Uint16LE.unpack(stream)
        return PointerPositionEvent(Point(x, y))

    def writePositionevent(self, stream, event):
        Uint16LE.pack(event.point.x, stream)
        Uint16LE.pack(event.point.y, stream)

    def parseColorEvent(self, stream):
        cacheIndex = Uint16LE.unpack(stream)
        hotSpot = Uint32LE.unpack(stream)
        width = Uint16LE.unpack(stream)
        height = Uint16LE.unpack(stream)
        andMaskLength = Uint16LE.unpack(stream)
        xorMaskLength = Uint16LE.unpack(stream)
        xorMask = stream.read(xorMaskLength)
        andMask = stream.read(andMaskLength)
        stream.read(1)

        return PointerColorEvent(cacheIndex, hotSpot, width, height, andMask, xorMask)

    def writeColorEvent(self, stream, event):
        Uint16LE.pack(event.cacheIndex, stream)
        Uint32LE.pack(event.hotSpot, stream)
        Uint16LE.pack(event.width, stream)
        Uint16LE.pack(event.height, stream)
        Uint16LE.pack(len(event.andMask), stream)
        Uint16LE.pack(len(event.xorMask), stream)
        stream.write(event.xorMask)
        stream.write(event.andMask)
        stream.write(b"\x00")

    def parseCacheEvent(self, stream):
        cacheIndex = Uint16LE.unpack(stream)
        return PointerCacheEvent(cacheIndex)

    def writeCacheEvent(self, stream, event):
        Uint16LE.pack(event.cacheIndex, stream)

    def parseNewEvent(self, stream):
        xorBPP = Uint16LE.unpack(stream)
        color = self.parseColorEvent(stream)
        return PointerNewEvent(xorBPP, color)

    def writeNewEvent(self, stream, event):
        Uint16LE.pack(event.xorBPP, stream)
        self.writeColorEvent(stream, event.color)