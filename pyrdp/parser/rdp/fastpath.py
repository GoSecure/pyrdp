#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import typing
from binascii import hexlify
from io import BytesIO

from pyrdp.core import Uint16BE, Uint16LE, Uint8
from pyrdp.enum import EncryptionMethod, FastPathInputType, \
    FastPathOutputCompressionType, FastPathOutputType, FastPathSecurityFlags, FIPSVersion, ParserMode
from pyrdp.pdu import FastPathBitmapEvent, FastPathEventRaw, FastPathMouseEvent, FastPathOrdersEvent, FastPathPDU, \
    FastPathScanCodeEvent
from pyrdp.pdu.rdp.fastpath import FastPathEvent, FastPathOutputEvent, FastPathUnicodeEvent
from pyrdp.security import RC4Crypter, RC4CrypterProxy

from pyrdp.parser.parser import Parser
from pyrdp.parser.rdp.bitmap import BitmapParser
from pyrdp.parser.rdp.security import BasicSecurityParser

from pyrdp.logging import log


class BasicFastPathParser(BasicSecurityParser):
    def __init__(self, mode: ParserMode):
        super().__init__()

        self.mode = mode
        input, output = FastPathInputParser(), FastPathOutputParser()

        if mode == ParserMode.CLIENT:
            self.readParser = output
            self.writeParser = input
        else:
            self.readParser = input
            self.writeParser = output

    def getPDULength(self, data: bytes) -> int:
        stream = BytesIO(data)
        stream.read(1)
        return self.parseLength(stream)

    def isCompletePDU(self, data: bytes) -> bool:
        if len(data) == 1:
            return False

        if Uint8.unpack(data[1]) & 0x80 != 0 and len(data) == 2:
            return False

        return len(data) >= self.getPDULength(data)

    def parse(self, data: bytes) -> FastPathPDU:
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.tell())
        events = self.parseEvents(data)
        return FastPathPDU(header, events)

    def parseEventCount(self, header: int) -> int:
        if self.mode == ParserMode.SERVER:
            return (header >> 2) & 0xf
        else:
            return 1

    def parseLength(self, stream: BytesIO) -> int:
        length = Uint8.unpack(stream)

        if length & 0x80 != 0:
            length = ((length & 0x7f) << 8) | Uint8.unpack(stream)

        return length

    def parseEvents(self, data: bytes) -> [FastPathEvent]:
        events = []

        while len(data) > 0:
            eventLength = self.readParser.getEventLength(data)
            eventData = data[: eventLength]
            data = data[eventLength:]

            try:
                event = self.readParser.parse(eventData)
            except KeyboardInterrupt:
                raise
            except Exception:
                log.error("Exception occurred when receiving: %(data)s", {"data": hexlify(eventData)})
                raise

            events.append(event)

        return events

    def writeHeader(self, stream: BytesIO, pdu: FastPathPDU):
        header = (pdu.header & 0xc0) | self.getHeaderFlags()
        eventCount = len(pdu.events)

        if eventCount <= 15 and self.mode == ParserMode.CLIENT:
            header |= eventCount << 2

        Uint8.pack(header, stream)
        self.writeLength(stream, pdu)

    def writeBody(self, stream: BytesIO, pdu: FastPathPDU):
        eventCount = len(pdu.events)

        if self.mode == ParserMode.CLIENT and eventCount > 15:
            Uint8.pack(eventCount, stream)

    def writePayload(self, stream: BytesIO, pdu: FastPathPDU):
        self.writeEvents(stream, pdu)

    def writeLength(self, stream: BytesIO, pdu: FastPathPDU):
        length = self.calculatePDULength(pdu)
        Uint16BE.pack(length | 0x8000, stream)

    def writeEvents(self, stream: BytesIO, pdu: FastPathPDU):
        for event in pdu.events:
            eventData = self.writeParser.write(event)
            stream.write(eventData)

    def calculatePDULength(self, pdu: FastPathPDU) -> int:
        # Header + length bytes
        length = 3
        length += sum(self.writeParser.getEventLength(event) for event in pdu.events)

        if self.mode == ParserMode.CLIENT and len(pdu.events) > 15:
            length += 1

        return length

    def getHeaderFlags(self) -> int:
        return 0


class SignedFastPathParser(BasicFastPathParser):
    def __init__(self, crypter: RC4Crypter, mode: ParserMode):
        BasicFastPathParser.__init__(self, mode)
        self.crypter = crypter
        self.eventData = b""

    def parse(self, data: bytes) -> FastPathPDU:
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)
        _signature = stream.read(8)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.tell())

        if header & FastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED != 0:
            data = self.crypter.decrypt(data)
            self.crypter.addDecryption()

        events = self.parseEvents(data)
        return FastPathPDU(header, events)

    def writeBody(self, stream: BytesIO, pdu: FastPathPDU):
        eventStream = BytesIO()
        self.writeEvents(eventStream, pdu)
        self.eventData = eventStream.getvalue()
        signature = self.crypter.sign(self.eventData, True)

        stream.write(signature)
        BasicFastPathParser.writeBody(self, stream, pdu)

    def writePayload(self, stream: BytesIO, pdu: FastPathPDU):
        eventData = self.crypter.encrypt(self.eventData)
        self.crypter.addEncryption()
        self.eventData = b""

        stream.write(eventData)

    def calculatePDULength(self, pdu: FastPathPDU) -> int:
        return BasicFastPathParser.calculatePDULength(self, pdu) + 8

    def getHeaderFlags(self) -> FastPathSecurityFlags:
        return FastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED | FastPathSecurityFlags.FASTPATH_OUTPUT_SECURE_CHECKSUM


class FIPSFastPathParser(SignedFastPathParser):
    def __init__(self, crypter: RC4Crypter, mode: ParserMode):
        SignedFastPathParser.__init__(self, crypter, mode)

    def parse(self, data: bytes) -> FastPathPDU:
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)
        _fipsLength = Uint16LE.unpack(stream)
        _version = Uint8.unpack(stream)
        _padLength = Uint8.unpack(stream)
        _signature = stream.read(8)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.tell())

        if header & FastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED != 0:
            data = self.crypter.decrypt(data)
            self.crypter.addDecryption()

        events = self.parseEvents(data)
        return FastPathPDU(header, events)

    def writeBody(self, stream: BytesIO, pdu: FastPathPDU):
        bodyStream = BytesIO()
        SignedFastPathParser.writeBody(self, bodyStream, pdu)
        body = bodyStream.getvalue()

        Uint16LE.pack(0x10, stream)
        Uint8.pack(FIPSVersion.TSFIPS_VERSION1, stream)
        Uint8.pack(self.crypter.getPadLength(self.eventData), stream)
        stream.write(body)

    def calculatePDULength(self, pdu: FastPathPDU) -> int:
        return super().calculatePDULength(pdu) + 4


class FastPathInputParser(Parser):
    INPUT_EVENT_LENGTHS = {
        FastPathInputType.FASTPATH_INPUT_EVENT_SCANCODE: 2,
        FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE: 7,
        FastPathInputType.FASTPATH_INPUT_EVENT_MOUSEX: 7,
        FastPathInputType.FASTPATH_INPUT_EVENT_SYNC: 1,
        FastPathInputType.FASTPATH_INPUT_EVENT_UNICODE: 3,
        FastPathInputType.FASTPATH_INPUT_EVENT_QOE_TIMESTAMP: 5,
    }

    def getEventLength(self, data: bytes) -> int:
        if isinstance(data, FastPathEventRaw):
            return len(data.data)
        elif isinstance(data, bytes):
            header = Uint8.unpack(data[0])
            type = (header & 0b11100000) >> 5
            return FastPathInputParser.INPUT_EVENT_LENGTHS[type]
        elif isinstance(data, FastPathScanCodeEvent):
            return FastPathInputParser.INPUT_EVENT_LENGTHS[FastPathInputType.FASTPATH_INPUT_EVENT_SCANCODE]
        elif isinstance(data, FastPathMouseEvent):
            return FastPathInputParser.INPUT_EVENT_LENGTHS[FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE]
        elif isinstance(data, FastPathUnicodeEvent):
            return FastPathInputParser.INPUT_EVENT_LENGTHS[FastPathInputType.FASTPATH_INPUT_EVENT_UNICODE]

        raise ValueError("Unsupported event type?")

    def parse(self, data: bytes) -> FastPathEvent:
        stream = BytesIO(data)
        eventHeader = Uint8.unpack(stream.read(1))
        eventCode = (eventHeader & 0b11100000) >> 5
        eventFlags = eventHeader & 0b00011111

        if eventCode == FastPathInputType.FASTPATH_INPUT_EVENT_SCANCODE:
            return self.parseScanCodeEvent(eventFlags, eventHeader, stream)
        elif eventCode == FastPathInputType.FASTPATH_INPUT_EVENT_MOUSE:
            return self.parseMouseEvent(eventHeader, stream)
        elif eventCode == FastPathInputType.FASTPATH_INPUT_EVENT_UNICODE:
            return self.parseUnicodeEvent(eventHeader, stream)

        return FastPathEventRaw(data)

    def parseScanCodeEvent(self, eventFlags: int, eventHeader: int, stream: BytesIO) -> FastPathScanCodeEvent:
        scanCode = Uint8.unpack(stream.read(1))
        return FastPathScanCodeEvent(eventHeader, scanCode, eventFlags & 1 != 0)

    def parseMouseEvent(self, eventHeader: int, stream: BytesIO) -> FastPathMouseEvent:
        pointerFlags = Uint16LE.unpack(stream)
        mouseX = Uint16LE.unpack(stream)
        mouseY = Uint16LE.unpack(stream)
        return FastPathMouseEvent(eventHeader, pointerFlags, mouseX, mouseY)

    def parseUnicodeEvent(self, eventHeader: int, stream: BytesIO) -> FastPathUnicodeEvent:
        released = eventHeader & 1 != 0
        text = stream.read(2)

        try:
            text = text.decode("utf-16le")
        except UnicodeError:
            pass

        return FastPathUnicodeEvent(text, released)

    def write(self, event: FastPathEvent) -> bytes:
        if isinstance(event, FastPathEventRaw):
            return event.data
        elif isinstance(event, FastPathScanCodeEvent):
            return self.writeScanCodeEvent(event)
        elif isinstance(event, FastPathMouseEvent):
            return self.writeMouseEvent(event)
        elif isinstance(event, FastPathUnicodeEvent):
            return self.writeUnicodeEvent(event)

        raise ValueError("Invalid FastPath event: {}".format(event))

    def writeScanCodeEvent(self, event: FastPathScanCodeEvent) -> bytes:
        stream = BytesIO()
        Uint8.pack(event.rawHeaderByte | int(event.isReleased), stream)
        Uint8.pack(event.scanCode, stream)
        return stream.getvalue()

    def writeMouseEvent(self, event: FastPathMouseEvent) -> bytes:
        stream = BytesIO()
        Uint8.pack(event.rawHeaderByte, stream)
        Uint16LE.pack(event.pointerFlags, stream)
        Uint16LE.pack(event.mouseX, stream)
        Uint16LE.pack(event.mouseY, stream)
        return stream.getvalue()

    def writeUnicodeEvent(self, event: FastPathUnicodeEvent):
        stream = BytesIO()
        Uint8.pack(int(event.released) | (FastPathInputType.FASTPATH_INPUT_EVENT_UNICODE << 5), stream)

        if isinstance(event.text, bytes):
            stream.write(event.text[: 2].ljust(2, b"\x00"))
        elif isinstance(event.text, str):
            stream.write(event.text[: 1].ljust(1, "\x00").encode("utf-16le"))

        return stream.getvalue()


class FastPathOutputParser(Parser):
    def __init__(self):
        super().__init__()
        self.bitmapParser = BitmapParser()

    def getEventLength(self, event: FastPathOutputEvent) -> int:
        if isinstance(event, bytes):
            header = Uint8.unpack(event[0])
            if self.isCompressed(header):
                return Uint16LE.unpack(event[2: 4]) + 4
            else:
                return Uint16LE.unpack(event[1: 3]) + 3

        size = 3

        if self.isCompressed(event.header):
            size += 1

        if isinstance(event, FastPathOrdersEvent):
            size += len(event.payload)
        elif isinstance(event, FastPathBitmapEvent):
            size += len(event.payload)
        elif isinstance(event, FastPathOutputEvent):
            length = len(event.payload) + 3
            if event.compressionFlags is not None:
                length += 1
            return length

        return size

    def isCompressed(self, header: int) -> bool:
        return (header >> 6) & FastPathOutputCompressionType.FASTPATH_OUTPUT_COMPRESSION_USED != 0

    def parse(self, data: bytes) -> FastPathOutputEvent:
        """
        Parse TS_FP_UPDATE.

        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a1c4caa8-00ed-45bb-a06e-5177473766d3
        """
        stream = BytesIO(data)
        header = Uint8.unpack(stream)

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a1c4caa8-00ed-45bb-a06e-5177473766d3
        updateCode = header & 0xf
        # fragmentation = (header & 0b00110000) >> 4
        compressionFlags = Uint8.unpack(stream) if self.isCompressed(header) else None
        size = Uint16LE.unpack(stream)

        # Dispatch to the appropriate sub-parser.
        if updateCode == FastPathOutputType.FASTPATH_UPDATETYPE_BITMAP:
            return self.parseBitmapEventRaw(stream, header, compressionFlags, size)
        elif updateCode == FastPathOutputType.FASTPATH_UPDATETYPE_ORDERS:
            return self.parseOrdersEvent(stream, header, compressionFlags, size)

        read = stream.read(size)
        return FastPathOutputEvent(header, compressionFlags, read)

    def parseBitmapEventRaw(self, stream: BytesIO, header: int, compressionFlags: int, size: int) -> FastPathBitmapEvent:
        return FastPathBitmapEvent(header, compressionFlags, [], stream.read(size))

    def parseBitmapEvent(self, fastPathBitmapEvent: FastPathOutputEvent) -> FastPathBitmapEvent:
        rawBitmapUpdateData = fastPathBitmapEvent.payload
        stream = BytesIO(rawBitmapUpdateData)
        updateType = Uint16LE.unpack(stream.read(2))
        bitmapData = self.bitmapParser.parseBitmapUpdateData(stream.read())

        return FastPathBitmapEvent(fastPathBitmapEvent.header, fastPathBitmapEvent.compressionFlags, bitmapData, rawBitmapUpdateData)

    def writeBitmapEvent(self, stream: BytesIO, event: FastPathBitmapEvent):
        stream.write(event.payload)

    def parseOrdersEvent(self, stream: BytesIO, header: int, compressionFlags: int, size: int) -> FastPathOrdersEvent:
        """
        Parse the order events from a TS_FP_UPDATE_ORDERS.
        This is specified in MS-RDPEGDI.
        """
        payload = stream.read(size)
        assert len(payload) == size

        orders = FastPathOrdersEvent(header, compressionFlags, payload)
        return orders

    def writeOrdersEvent(self, stream, event):
        # Just write the saved raw bytes as-is.
        stream.write(event.payload)

    def write(self, event: FastPathOutputEvent) -> bytes:

        stream = BytesIO()
        Uint8.pack(event.header, stream)

        if event.compressionFlags is not None:
            Uint8.pack(event.compressionFlags if event.compressionFlags else 0, stream)

        updateStream = BytesIO()

        if isinstance(event, FastPathBitmapEvent):
            self.writeBitmapEvent(updateStream, event)
        elif isinstance(event, FastPathOrdersEvent):
            self.writeOrdersEvent(updateStream, event)
        else:
            # Means it's simply a FastPathOutputUpdateEvent, this needs to be the last elif.
            updateStream.write(event.payload)

        updateData = updateStream.getvalue()
        Uint16LE.pack(len(updateData), stream)
        stream.write(updateData)
        return stream.getvalue()


def createFastPathParser(tls: bool,
                         encryptionMethod: EncryptionMethod,
                         crypter: typing.Union[RC4Crypter, RC4CrypterProxy],
                         mode: ParserMode) -> typing.Union[BasicFastPathParser, SignedFastPathParser, FIPSFastPathParser]:
    """
    Create a fast-path parser based on which encryption method is used.
    :param tls: whether TLS is used or not.
    :param encryptionMethod: the encryption method.
    :param crypter: the crypter for this connection.
    :param mode: the fast-path parser mode.
    """
    if tls:
        return BasicFastPathParser(mode)
    elif encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
        return SignedFastPathParser(crypter, mode)
    elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
        return FIPSFastPathParser(crypter, mode)
    else:
        raise ValueError("Invalid fast-path layer mode")
