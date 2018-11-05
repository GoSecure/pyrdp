from StringIO import StringIO

from rdpy.core import log

from rdpy.core.packing import Uint8, Uint16BE, Uint16LE
from rdpy.enum.rdp import RDPFastPathParserMode, RDPFastPathInputEventType, \
    RDPFastPathSecurityFlags, FIPSVersion, FastPathOutputCompressionType, RDPFastPathOutputEventType
from rdpy.parser.rdp.security import RDPBasicSecurityParser
from rdpy.pdu.rdp.fastpath import FastPathEventRaw, RDPFastPathPDU, FastPathBitmapEvent, FastPathOrdersEvent


class RDPBasicFastPathParser(RDPBasicSecurityParser):
    def __init__(self, mode):
        self.mode = mode
        input, output = RDPInputEventParser(), RDPOutputEventParser()

        if mode == RDPFastPathParserMode.CLIENT:
            self.readParser = output
            self.writeParser = input
        else:
            self.readParser = input
            self.writeParser = output

    def getPDULength(self, data):
        stream = StringIO(data)
        stream.read(1)
        return self.parseLength(stream)

    def isCompletePDU(self, data):
        if len(data) == 1:
            return False

        if Uint8.unpack(data[1]) & 0x80 != 0 and len(data) == 2:
            return False

        return len(data) >= self.getPDULength(data)

    def parse(self, data):
        stream = StringIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.pos)
        events = self.parseEvents(data)
        return RDPFastPathPDU(header, events)

    def parseEventCount(self, header):
        if self.mode == RDPFastPathParserMode.SERVER:
            return (header >> 2) & 0xf
        else:
            return 1

    def parseLength(self, stream):
        length = Uint8.unpack(stream)

        if length & 0x80 != 0:
            length = ((length & 0x7f) << 8) | Uint8.unpack(stream)

        return length

    def parseEvents(self, data):
        events = []

        while len(data) > 0:
            eventLength = self.readParser.getEventLength(data)
            eventData = data[: eventLength]
            data = data[eventLength :]

            event = self.readParser.parse(eventData)
            events.append(event)

        return events

    def writeHeader(self, stream, pdu):
        header = (pdu.header & 0xc0) | self.getHeaderFlags()
        eventCount = len(pdu.events)

        if eventCount <= 15 and self.mode == RDPFastPathParserMode.CLIENT:
            header |= eventCount << 2

        Uint8.pack(header, stream)
        self.writeLength(stream, pdu)

    def writeBody(self, stream, pdu):
        eventCount = len(pdu.events)

        if self.mode == RDPFastPathParserMode.CLIENT and eventCount > 15:
            Uint8.pack(eventCount, stream)

    def writePayload(self, stream, pdu):
        self.writeEvents(stream, pdu)

    def writeLength(self, stream, pdu):
        length = self.calculatePDULength(pdu)
        Uint16BE.pack(length | 0x8000, stream)

    def writeEvents(self, stream, pdu):
        for event in pdu.events:
            eventData = self.writeParser.write(event)
            stream.write(eventData)

    def calculatePDULength(self, pdu):
        # Header + length bytes
        length = 3
        length += sum(self.writeParser.getEventLength(event) for event in pdu.events)

        if self.mode == RDPFastPathParserMode.CLIENT and len(pdu.events) > 15:
            length += 1

        return length

    def getHeaderFlags(self):
        return 0



class RDPSignedFastPathParser(RDPBasicFastPathParser):
    def __init__(self, crypter, mode):
        RDPBasicFastPathParser.__init__(self, mode)
        self.crypter = crypter
        self.eventData = ""

    def parse(self, data):
        stream = StringIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)
        signature = stream.read(8)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.pos)

        if header & RDPFastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED != 0:
            data = self.crypter.decrypt(data)
            self.crypter.addDecryption()

        events = self.parseEvents(data)
        return RDPFastPathPDU(header, events)

    def writeBody(self, stream, pdu):
        eventStream = StringIO()
        self.writeEvents(eventStream, pdu)
        self.eventData = eventStream.getvalue()
        signature = self.crypter.sign(self.eventData, True)

        stream.write(signature)
        RDPBasicFastPathParser.writeBody(self, stream, pdu)

    def writePayload(self, stream, pdu):
        eventData = self.crypter.encrypt(self.eventData)
        self.crypter.addEncryption()
        self.eventData = ""

        stream.write(eventData)

    def calculatePDULength(self, pdu):
        return RDPBasicFastPathParser.calculatePDULength(self, pdu) + 8

    def getHeaderFlags(self):
        return RDPFastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED | RDPFastPathSecurityFlags.FASTPATH_OUTPUT_SECURE_CHECKSUM



class RDPFIPSFastPathParser(RDPSignedFastPathParser):
    def __init__(self, crypter, mode):
        RDPSignedFastPathParser.__init__(self, crypter, mode)

    def parse(self, data):
        stream = StringIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)
        fipsLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.pos)

        if header & RDPFastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED != 0:
            data = self.crypter.decrypt(data)
            self.crypter.addDecryption()

        events = self.parseEvents(data)
        return RDPFastPathPDU(header, events)

    def writeBody(self, stream, pdu):
        bodyStream = StringIO()
        RDPSignedFastPathParser.writeBody(self, bodyStream, pdu)
        body = bodyStream.getvalue()

        Uint16LE.pack(0x10, stream)
        Uint8.pack(FIPSVersion.TSFIPS_VERSION1, stream)
        Uint8.pack(self.crypter.getPadLength(self.eventData), stream)
        stream.write(body)

    def calculatePDULength(self, pdu):
        return RDPSignedFastPathParser.calculatePDULength(self, pdu) + 4



class RDPInputEventParser:
    INPUT_EVENT_LENGTHS = {
        RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_SCANCODE: 2,
        RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_MOUSE: 7,
        RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_MOUSEX: 7,
        RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_SYNC: 1,
        RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_UNICODE: 3,
        RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_QOE_TIMESTAMP: 5,
    }

    def getEventLength(self, data):
        if isinstance(data, FastPathEventRaw):
            return len(data.data)

        header = Uint8.unpack(data[0])
        type = (header & 0b11100000) >> 5
        return RDPInputEventParser.INPUT_EVENT_LENGTHS[type]

    def parse(self, data):
        return FastPathEventRaw(data)

    def write(self, event):
        if isinstance(event, FastPathEventRaw):
            return event.data



class RDPOutputEventParser:
    def getEventLength(self, data):
        if isinstance(data, FastPathEventRaw):
            return len(data.data)
        elif isinstance(data, str):
            header = Uint8.unpack(data[0])
            if self.isCompressed(header):
                return Uint16LE.unpack(data[2 : 4]) + 4
            else:
                return Uint16LE.unpack(data[1 : 3]) + 3

        size = 3

        if self.isCompressed(data.header):
            size += 1

        if isinstance(data, FastPathOrdersEvent):
            size += 2 + len(data.orderData)
        elif isinstance(data, FastPathBitmapEvent):
            size += len(data.bitmapUpdateData)

        return size

    def isCompressed(self, header):
        return (header >> 6) == FastPathOutputCompressionType.FASTPATH_OUTPUT_COMPRESSION_USED

    def parse(self, data):
        stream = StringIO(data)
        header = Uint8.unpack(stream)

        compressionFlags = None

        if self.isCompressed(header):
            compressionFlags = Uint8.unpack(stream)

        size = Uint16LE.unpack(stream)

        if header & 0xf == RDPFastPathOutputEventType.FASTPATH_UPDATETYPE_BITMAP:
            return self.parseBitmapEvent(stream, header, compressionFlags, size)
        elif header & 0xf == RDPFastPathOutputEventType.FASTPATH_UPDATETYPE_ORDERS:
            return self.parseOrdersEvent(stream, header, compressionFlags, size)

        return FastPathEventRaw(data)

    def parseBitmapEvent(self, stream, header, compressionFlags, size):
        bitmapUpdateData = stream.read(size)
        return FastPathBitmapEvent(header, compressionFlags, bitmapUpdateData)

    def writeBitmapEvent(self, stream, event):
        stream.write(event.bitmapUpdateData)

    def parseOrdersEvent(self, stream, header, compressionFlags, size):
        orderCount = Uint16LE.unpack(stream)
        orderData = stream.read(size - 2)
        assert len(orderData) == size - 2
        return FastPathOrdersEvent(header, compressionFlags, orderCount, orderData)

    def writeOrdersEvent(self, stream, event):
        Uint16LE.pack(event.orderCount, stream)
        stream.write(event.orderData)

    def write(self, event):
        if isinstance(event, FastPathEventRaw):
            return event.data

        stream = StringIO()
        Uint8.pack(event.header, stream)

        if event.compressionFlags is not None:
            Uint8.pack(event.compressionFlags if event.compressionFlags else 0, stream)

        updateStream = StringIO()

        if isinstance(event, FastPathBitmapEvent):
            self.writeBitmapEvent(updateStream, event)
        elif isinstance(event, FastPathOrdersEvent):
            self.writeOrdersEvent(updateStream, event)

        updateData = updateStream.getvalue()
        Uint16LE.pack(len(updateData), stream)
        stream.write(updateData)

        return stream.getvalue()