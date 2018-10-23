from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint8, Uint32LE
from rdpy.enum.rdp import RDPSecurityHeaderType, RDPSecurityFlags
from rdpy.exceptions import UnknownPDUTypeError, WritingError
from rdpy.pdu.rdp.security import RDPBasicSecurityPDU, RDPSignedSecurityPDU, RDPFIPSSecurityPDU, RDPSecurityExchangePDU


class RDPSecurityParser:
    def __init__(self, headerType):
        self.headerType = headerType

    def parse(self, data):
        """
        Read the provided byte stream and return a RDP security PDU from it
        :type data: str
        :return: RDPSecurityBasePDU
        """
        stream = StringIO(data)
        header = Uint32LE.unpack(stream)
        return self.parseHeader(stream, header)

    def parseHeader(self, stream, header, payloadLength = None):
        headerType = self.headerType if self.headerType != RDPSecurityHeaderType.NONE else RDPSecurityHeaderType.DEFAULT

        if header & RDPSecurityFlags.SEC_EXCHANGE_PKT:
            return self.parseSecurityExchange(stream, header)
        elif headerType == RDPSecurityHeaderType.BASIC:
            return self.parseBasicSecurity(stream, header, payloadLength)
        elif headerType == RDPSecurityHeaderType.SIGNED:
            return self.parseSignedSecurity(stream, header, payloadLength)
        elif headerType == RDPSecurityHeaderType.FIPS:
            return self.parseFIPSSecurity(stream, header, payloadLength)
        else:
            raise UnknownPDUTypeError("Trying to parse unknown security header type", self.headerType)

    def parseSecurityExchange(self, stream, header):
        """
        :type stream: StringIO
        :type header: int
        :return: RDPSecurityExchangePDU
        """
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(header, clientRandom)

    def parsePayload(self, stream, payloadLength):
        if payloadLength is None:
            return stream.read()
        else:
            return stream.read(payloadLength)

    def parseBasicSecurity(self, stream, header, payloadLength = None):
        """
        :type stream: StringIO
        :type header: int
        :type payloadLength: int | None
        :return: RDPBasicSecurityPDU
        """
        payload = self.parsePayload(stream, payloadLength)
        return RDPBasicSecurityPDU(header, payload)

    def parseSignedSecurity(self, stream, header, payloadLength = None):
        """
        :type stream: StringIO
        :type header: int
        :type payloadLength: int | None
        :return: RDPSignedSecurityPDU
        """
        signature = stream.read(8)
        payload = self.parsePayload(stream, payloadLength)
        return RDPSignedSecurityPDU(header, signature, payload)

    def parseFIPSSecurity(self, stream, header, payloadLength = None):
        """
        :type stream: StringIO
        :type header: int
        :type payloadLength: int | None
        :return: RDPFIPSSecurityPDU
        """
        headerLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = self.parsePayload(stream, payloadLength)
        return RDPFIPSSecurityPDU(header, version, padLength, signature, payload)

    def write(self, pdu):
        """
        Encode the provided PDU to a byte stream to send to the previous layer
        :type pdu: RDPSecurityExchangePDU | RDPBasicSecurityPDU | RDPSignedSecurityPDU | RDPFIPSSecurityPDU
        :return: str
        """
        header = Uint32LE.pack(pdu.header)
        return self.writeHeader(pdu, header)

    def writeHeader(self, pdu, header):
        if isinstance(pdu, RDPSecurityExchangePDU):
            return header + self.writeSecurityExchange(pdu)
        elif isinstance(pdu, RDPBasicSecurityPDU):
            return header + pdu.payload
        elif isinstance(pdu, RDPSignedSecurityPDU):
            return header + self.writeSignedHeader(pdu) + pdu.payload
        elif isinstance(pdu, RDPFIPSSecurityPDU):
            return header + self.writeFIPSHeader(pdu) + pdu.payload
        else:
            raise WritingError("Trying to write invalid PDU type")

    def writeSignedHeader(self, pdu):
        return pdu.signature[: 8]

    def writeFIPSHeader(self, pdu):
        return Uint16LE.pack(0x10) + Uint8.pack(pdu.version) + Uint8.pack(pdu.padLength) + pdu.signature[: 8]

    def writeSecurityExchange(self, pdu):
        return Uint32LE.pack(len(pdu.clientRandom)) + pdu.clientRandom



class RDPFastPathSecurityParser(RDPSecurityParser):
    def __init__(self, headerType):
        RDPSecurityParser.__init__(self, headerType)

    def parse(self, data):
        """
        Read the provided byte stream and return a RDP security PDU from it
        :type data: str
        :return: RDPSecurityBasePDU
        """
        stream = StringIO(data)
        header = Uint8.unpack(stream)
        length = Uint8.unpack(stream)

        if length & 0x80 != 0:
            length = ((length & 0x7f) << 8) | Uint8.unpack(stream)

        return self.parseHeader(stream, header, length)

    def calculatePDULength(self, pdu):
        # Header + first length byte
        length = 2
        length += len(pdu.payload)

        if isinstance(pdu, RDPFIPSSecurityPDU):
            length += 12
        elif isinstance(pdu, RDPSignedSecurityPDU):
            length += 8

        # The size of the PDU will be on 2 bytes
        if length > 127:
            length += 1

        return length

    def packLength(self, length):
        if length <= 127:
            return Uint8.pack(length)
        else:
            return Uint8.pack(((length & 0xff00) >> 8) | 0x80) + Uint8.pack(length & 0xff)

    def write(self, pdu):
        stream = StringIO()
        header = Uint8.pack(pdu.header)
        length = self.calculatePDULength(pdu)

        stream.write(header)
        stream.write(self.packLength(length))
        stream.write(self.writeHeader(pdu, header))
        return stream.getvalue()