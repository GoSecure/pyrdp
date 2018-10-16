from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16BE
from rdpy.enum.x224 import X224Header
from rdpy.pdu.x224 import X224ConnectionConfirmPDU, X224ConnectionRequestPDU, X224DisconnectRequestPDU, X224DataPDU, \
    X224ErrorPDU


class X224Parser:
    """
    @summary: Parser for X224 PDUs
    """

    def __init__(self):
        self.parsers = {
            X224Header.X224_TPDU_CONNECTION_REQUEST: self.parseConnectionRequest,
            X224Header.X224_TPDU_CONNECTION_CONFIRM: self.parseConnectionConfirm,
            X224Header.X224_TPDU_DISCONNECT_REQUEST: self.parseDisconnectRequest,
            X224Header.X224_TPDU_DATA: self.parseData,
            X224Header.X224_TPDU_ERROR: self.parseError,
        }

        self.writers = {
            X224Header.X224_TPDU_CONNECTION_REQUEST: self.writeConnectionRequest,
            X224Header.X224_TPDU_CONNECTION_CONFIRM: self.writeConnectionConfirm,
            X224Header.X224_TPDU_DISCONNECT_REQUEST: self.writeDisconnectRequest,
            X224Header.X224_TPDU_DATA: self.writeData,
            X224Header.X224_TPDU_ERROR: self.writeError,
        }

    def parse(self, data):
        length = Uint8.unpack(data[0])
        header = Uint8.unpack(data[1]) >> 4

        if length < 2 or len(data) < length:
            raise Exception("Invalid X224 length indicator")

        if header not in self.parsers:
            raise Exception("Unknown X224 header received")

        return self.parsers[header](data, length)

    def parseConnectionPDU(self, data, length, name):
        if length < 6:
            raise Exception("Invalid %s" % name)

        destination = Uint16BE.unpack(data[2 : 4])
        source = Uint16BE.unpack(data[4 : 6])
        options = Uint8.unpack(data[6])
        payload = data[7 :]

        if len(payload) != length - 6:
            raise Exception("Invalid length indicator for X224 %s" % name)

        return source, destination, options, payload

    def parseConnectionRequest(self, data, length):
        credit = Uint8.unpack(data[1]) & 0xf
        destination, source, options, payload = self.parseConnectionPDU(data, length, "Connection Request")
        return X224ConnectionRequestPDU(credit, destination, source, options, payload)

    def parseConnectionConfirm(self, data, length):
        credit = Uint8.unpack(data[1]) & 0xf
        destination, source, options, payload = self.parseConnectionPDU(data, length, "Connection Confirm")
        return X224ConnectionConfirmPDU(credit, destination, source, options, payload)

    def parseDisconnectRequest(self, data, length):
        destination, source, reason, payload = self.parseConnectionPDU(data, length, "Disconnect Request")
        return X224DisconnectRequestPDU(destination, source, reason, payload)

    def parseData(self, data, length):
        if length != 2:
            raise Exception("Invalid length indicator for X224 Data PDU")

        code = Uint8.unpack(data[1]) & 0xf
        sequence = Uint8.unpack(data[2])
        payload = data[3 :]

        return X224DataPDU(code & 1 == 1, sequence & 0x80 == 0x80, payload)

    def parseError(self, data, length):
        if length < 4:
            raise Exception("Invalid X224 Error PDU")

        destination = Uint16BE.unpack(data[2 : 4])
        cause = Uint8.unpack(data[4])
        payload = data[5 :]

        if len(payload) != length - 4:
            raise Exception("Invalid length indicator for X224 Error PDU")

        return X224ErrorPDU(destination, cause, payload)

    def write(self, pdu):
        stream = StringIO()
        stream.write(Uint8.pack(pdu.length))

        if pdu.header not in self.writers:
            raise Exception("Unknown X224 header")

        self.writers[pdu.header](stream, pdu)
        stream.write(pdu.payload)
        return stream.getvalue()

    def writeConnectionPDU(self, stream, header, destination, source, options):
        stream.write(Uint8.pack(header))
        stream.write(Uint16BE.pack(destination))
        stream.write(Uint16BE.pack(source))
        stream.write(Uint8.pack(options))

    def writeConnectionRequest(self, stream, pdu):
        header = (pdu.header << 4) | (pdu.credit & 0xf)
        self.writeConnectionPDU(stream, header, pdu.destination, pdu.source, pdu.options)

    def writeConnectionConfirm(self, stream, pdu):
        header = (pdu.header << 4) | (pdu.credit & 0xf)
        self.writeConnectionPDU(stream, header, pdu.destination, pdu.source, pdu.options)

    def writeDisconnectRequest(self, stream, pdu):
        self.writeConnectionPDU(stream, pdu.header, pdu.destination, pdu.source, pdu.reason)

    def writeData(self, stream, pdu):
        header = (pdu.header << 4) | int(pdu.roa)
        stream.write(Uint8.pack(header))
        stream.write(Uint8.pack(int(pdu.eot) << 7))

    def writeError(self, stream, pdu):
        stream.write(Uint8.pack(pdu.header))
        stream.write(Uint16.pack(pdu.destination))
        stream.write(Uint8.pack(pdu.cause))