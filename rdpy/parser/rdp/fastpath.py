from binascii import hexlify
from io import BytesIO

from rdpy.core.logging import log
from rdpy.core.packing import Uint8, Uint16BE, Uint16LE
from rdpy.crypto.crypto import RC4Crypter
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import RDPFastPathInputEventType, \
    RDPFastPathSecurityFlags, FIPSVersion, FastPathOutputCompressionType, RDPFastPathOutputEventType, \
    DrawingOrderControlFlags, EncryptionMethod
from rdpy.parser.parser import Parser
from rdpy.parser.rdp.common import RDPCommonParser
from rdpy.parser.rdp.security import RDPBasicSecurityParser
from rdpy.pdu.rdp.fastpath import FastPathEventRaw, RDPFastPathPDU, FastPathEventScanCode, FastPathBitmapEvent, \
    FastPathOrdersEvent, FastPathEventMouse, SecondaryDrawingOrder


class RDPBasicFastPathParser(RDPBasicSecurityParser):
    def __init__(self, mode):
        self.mode = mode
        input, output = RDPInputEventParser(), RDPOutputEventParser()

        if mode == ParserMode.CLIENT:
            self.readParser = output
            self.writeParser = input
        else:
            self.readParser = input
            self.writeParser = output

    def getPDULength(self, data):
        stream = BytesIO(data)
        stream.read(1)
        return self.parseLength(stream)

    def getPDULengthWithSocket(self, socket):
        """
        Same as getPDULength, but with a network socket.
        :type socket: socket.socket
        """
        data = socket.recv(1)
        data2, length = self.parseLengthWithSocket(socket)
        data += data2
        return data, length

    def isCompletePDU(self, data):
        if len(data) == 1:
            return False

        if Uint8.unpack(data[1]) & 0x80 != 0 and len(data) == 2:
            return False

        return len(data) >= self.getPDULength(data)

    def parse(self, data):
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.tell())
        events = self.parseEvents(data)
        return RDPFastPathPDU(header, events)

    def parseEventCount(self, header):
        if self.mode == ParserMode.SERVER:
            return (header >> 2) & 0xf
        else:
            return 1

    def parseLength(self, stream):
        length = Uint8.unpack(stream)

        if length & 0x80 != 0:
            length = ((length & 0x7f) << 8) | Uint8.unpack(stream)

        return length

    def parseLengthWithSocket(self, socket):
        """
        Same as parseLength, but with a network socket.
        :type socket: socket.socket
        """
        data = socket.recv(1)
        length = Uint8.unpack(data)

        if length & 0x80 != 0:
            data2 = socket.recv(1)
            data += data2
            length = ((length & 0x7f) << 8) | Uint8.unpack(data2)

        return data, length

    def parseEvents(self, data):
        events = []

        while len(data) > 0:
            eventLength = self.readParser.getEventLength(data)
            eventData = data[: eventLength]
            data = data[eventLength :]

            try:
                event = self.readParser.parse(eventData)
            except KeyboardInterrupt:
                raise
            except Exception:
                log.error("Exception occurred when receiving: %(data)s", {"data": hexlify(eventData.encode)})
                raise

            events.append(event)

        return events

    def writeHeader(self, stream, pdu):
        header = (pdu.header & 0xc0) | self.getHeaderFlags()
        eventCount = len(pdu.events)

        if eventCount <= 15 and self.mode == ParserMode.CLIENT:
            header |= eventCount << 2

        Uint8.pack(header, stream)
        self.writeLength(stream, pdu)

    def writeBody(self, stream, pdu):
        eventCount = len(pdu.events)

        if self.mode == ParserMode.CLIENT and eventCount > 15:
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

        if self.mode == ParserMode.CLIENT and len(pdu.events) > 15:
            length += 1

        return length

    def getHeaderFlags(self):
        return 0


class RDPSignedFastPathParser(RDPBasicFastPathParser):
    def __init__(self, crypter, mode):
        RDPBasicFastPathParser.__init__(self, mode)
        self.crypter = crypter
        self.eventData = b""

    def parse(self, data):
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)
        signature = stream.read(8)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.tell())

        if header & RDPFastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED != 0:
            data = self.crypter.decrypt(data)
            self.crypter.addDecryption()

        events = self.parseEvents(data)
        return RDPFastPathPDU(header, events)

    def writeBody(self, stream, pdu):
        eventStream = BytesIO()
        self.writeEvents(eventStream, pdu)
        self.eventData = eventStream.getvalue()
        signature = self.crypter.sign(self.eventData, True)

        stream.write(signature)
        RDPBasicFastPathParser.writeBody(self, stream, pdu)

    def writePayload(self, stream, pdu):
        eventData = self.crypter.encrypt(self.eventData)
        self.crypter.addEncryption()
        self.eventData = b""

        stream.write(eventData)

    def calculatePDULength(self, pdu):
        return RDPBasicFastPathParser.calculatePDULength(self, pdu) + 8

    def getHeaderFlags(self):
        return RDPFastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED | RDPFastPathSecurityFlags.FASTPATH_OUTPUT_SECURE_CHECKSUM



class RDPFIPSFastPathParser(RDPSignedFastPathParser):
    def __init__(self, crypter, mode):
        RDPSignedFastPathParser.__init__(self, crypter, mode)

    def parse(self, data):
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        eventCount = self.parseEventCount(header)
        pduLength = self.parseLength(stream)
        fipsLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)

        if eventCount == 0:
            eventCount = Uint8.unpack(stream)

        data = stream.read(pduLength - stream.tell())

        if header & RDPFastPathSecurityFlags.FASTPATH_OUTPUT_ENCRYPTED != 0:
            data = self.crypter.decrypt(data)
            self.crypter.addDecryption()

        events = self.parseEvents(data)
        return RDPFastPathPDU(header, events)

    def writeBody(self, stream, pdu):
        bodyStream = BytesIO()
        RDPSignedFastPathParser.writeBody(self, bodyStream, pdu)
        body = bodyStream.getvalue()

        Uint16LE.pack(0x10, stream)
        Uint8.pack(FIPSVersion.TSFIPS_VERSION1, stream)
        Uint8.pack(self.crypter.getPadLength(self.eventData), stream)
        stream.write(body)

    def calculatePDULength(self, pdu):
        return RDPSignedFastPathParser.calculatePDULength(self, pdu) + 4


class RDPInputEventParser(Parser):
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
        elif isinstance(data, bytes):
            header = Uint8.unpack(data[0])
            type = (header & 0b11100000) >> 5
            return RDPInputEventParser.INPUT_EVENT_LENGTHS[type]
        elif isinstance(data, FastPathEventScanCode):
            return RDPInputEventParser.INPUT_EVENT_LENGTHS[RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_SCANCODE]
        elif isinstance(data, FastPathEventMouse):
            return RDPInputEventParser.INPUT_EVENT_LENGTHS[RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_MOUSE]
        raise ValueError("Unsupported event type?")

    def parse(self, data):
        stream = BytesIO(data)
        eventHeader = Uint8.unpack(stream.read(1))
        eventCode = (eventHeader & 0b11100000) >> 5
        eventFlags= eventHeader & 0b00011111
        if eventCode == RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_SCANCODE:
            return self.parseScanCode(eventFlags, eventHeader, stream)
        elif eventCode == RDPFastPathInputEventType.FASTPATH_INPUT_EVENT_MOUSE:
            return self.parseMouseEvent(data, eventHeader)
        return FastPathEventRaw(data)

    def parseMouseEvent(self, data, eventHeader):
        pointerFlags = Uint16LE.unpack(data[1:3])
        mouseX = Uint16LE.unpack(data[3:5])
        mouseY = Uint16LE.unpack(data[5:7])
        return FastPathEventMouse(eventHeader, pointerFlags, mouseX, mouseY)

    def parseScanCode(self, eventFlags, eventHeader, stream):
        scancode = Uint8.unpack(stream.read(1))
        return FastPathEventScanCode(eventHeader, scancode, eventFlags)

    def write(self, event):
        if isinstance(event, FastPathEventRaw):
            return event.data
        elif isinstance(event, FastPathEventScanCode):
            return self.writeScanCodeEvent(event)
        elif isinstance(event, FastPathEventMouse):
            return self.writeMouseEvent(event)
        raise ValueError("Invalid FastPath event: {}".format(event))

    def writeScanCodeEvent(self, event):
        raw_data = BytesIO()
        Uint8.pack(event.rawHeaderByte, raw_data)
        Uint8.pack(event.scancode, raw_data)
        return raw_data.getvalue()

    def writeMouseEvent(self, event):
        rawData = BytesIO()
        Uint8.pack(event.rawHeaderByte, rawData)
        Uint16LE.pack(event.pointerFlags, rawData)
        Uint16LE.pack(event.mouseX, rawData)
        Uint16LE.pack(event.mouseY, rawData)
        return rawData.getvalue()


class RDPOutputEventParser(Parser):
    def getEventLength(self, data):
        if isinstance(data, FastPathEventRaw):
            return len(data.data)
        elif isinstance(data, bytes):
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
            size += len(data.rawBitmapUpdateData)

        return size

    def isCompressed(self, header):
        return (header >> 6) & FastPathOutputCompressionType.FASTPATH_OUTPUT_COMPRESSION_USED

    def parse(self, data):
        stream = BytesIO(data)
        header = Uint8.unpack(stream)

        compressionFlags = None

        if self.isCompressed(header):
            compressionFlags = Uint8.unpack(stream)

        size = Uint16LE.unpack(stream)

        eventType = header & 0xf
        fragmentation = header & 0b00110000 != 0
        if fragmentation:
            log.error("Fragmentation is present in fastpath packets, it is NOT handled.")

        if eventType == RDPFastPathOutputEventType.FASTPATH_UPDATETYPE_BITMAP:
            return self.parseBitmapEventRaw(stream, header, compressionFlags, size)
        elif eventType == RDPFastPathOutputEventType.FASTPATH_UPDATETYPE_ORDERS:
            return self.parseOrdersEvent(stream, header, compressionFlags, size)

        return FastPathEventRaw(data)

    def parseBitmapEventRaw(self, stream, header, compressionFlags, size):
        return FastPathBitmapEvent(header, compressionFlags, None, stream.read(size))

    def parseBitmapEvent(self, fastPathBitmapEvent):
        """
        :type fastPathBitmapEvent: FastPathBitmapEvent
        :return: a FastPathBitmapEvent with bitmapUpdateData
        """
        rawBitmapUpdateData = fastPathBitmapEvent.rawBitmapUpdateData
        stream = BytesIO(rawBitmapUpdateData)
        updateType = Uint16LE.unpack(stream.read(2))
        bitmapData = RDPCommonParser().parseBitmapUpdateData(stream.read())

        return FastPathBitmapEvent(fastPathBitmapEvent.header, fastPathBitmapEvent.compressionFlags,
                                   bitmapData, rawBitmapUpdateData)

    def writeBitmapEvent(self, stream, event):
        stream.write(event.rawBitmapUpdateData)

    def parseOrdersEvent(self, stream, header, compressionFlags, size):
        orderCount = Uint16LE.unpack(stream)
        orderData = stream.read(size - 2)
        assert len(orderData) == size - 2
        ordersEvent = FastPathOrdersEvent(header, compressionFlags, orderCount, orderData)
        controlFlags = Uint8.unpack(orderData[0])
        if controlFlags & (DrawingOrderControlFlags.TS_SECONDARY | DrawingOrderControlFlags.TS_STANDARD)\
                == (DrawingOrderControlFlags.TS_SECONDARY | DrawingOrderControlFlags.TS_STANDARD):
            ordersEvent.secondaryDrawingOrders = self.parseSecondaryDrawingOrder(orderData)
        elif controlFlags & DrawingOrderControlFlags.TS_SECONDARY:
            pass
        return ordersEvent

    def parseSecondaryDrawingOrder(self, orderData):
        stream = BytesIO(orderData)
        controlFlags = Uint8.unpack(stream.read(1))
        orderLength = Uint16LE.unpack(stream.read(2))
        extraFlags = Uint16LE.unpack(stream.read(2))
        orderType = Uint8.unpack(stream.read(1))
        return SecondaryDrawingOrder(controlFlags, orderLength, extraFlags, orderType, stream.read())

    def writeOrdersEvent(self, stream, event):
        Uint16LE.pack(event.orderCount, stream)
        stream.write(event.orderData)

    def write(self, event):
        if isinstance(event, FastPathEventRaw):
            return event.data

        stream = BytesIO()
        Uint8.pack(event.header, stream)

        if event.compressionFlags is not None:
            Uint8.pack(event.compressionFlags if event.compressionFlags else 0, stream)

        updateStream = BytesIO()

        if isinstance(event, FastPathBitmapEvent):
            self.writeBitmapEvent(updateStream, event)
        elif isinstance(event, FastPathOrdersEvent):
            self.writeOrdersEvent(updateStream, event)

        updateData = updateStream.getvalue()
        Uint16LE.pack(len(updateData), stream)
        stream.write(updateData)

        return stream.getvalue()


def createFastPathParser(tls, encryptionMethod, crypter, mode):
    """
    Create a fast-path parser based on which encryption method is used.
    :param tls: whether TLS is used or not.
    :type tls: bool
    :param encryptionMethod: the encryption method.
    :type encryptionMethod: EncryptionMethod
    :param crypter: the crypter for this connection.
    :type crypter: RC4Crypter | RC4CrypterProxy
    :param mode: the fast-path parser mode.
    :type mode: ParserMode
    """
    if tls:
        return RDPBasicFastPathParser(mode)
    elif encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
        return RDPSignedFastPathParser(crypter, mode)
    elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
        return RDPFIPSFastPathParser(crypter, mode)
    else:
        raise ValueError("Invalid fast-path layer mode")