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
        headerType = self.headerType if self.headerType != RDPSecurityHeaderType.NONE else RDPSecurityHeaderType.DEFAULT
        header = Uint32LE.unpack(stream)

        if header & RDPSecurityFlags.SEC_EXCHANGE_PKT:
            return self.parseSecurityExchange(stream, header)
        elif headerType == RDPSecurityHeaderType.BASIC:
            return self.parseBasicSecurity(stream, header)
        elif self.headerType == RDPSecurityHeaderType.SIGNED:
            return self.parseSignedSecurity(stream, header)
        elif self.headerType == RDPSecurityHeaderType.FIPS:
            return self.parseFIPSSecurity(stream, header)
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

    def parseBasicSecurity(self, stream, header):
        """
        :type stream: StringIO
        :type header: int
        :return: RDPBasicSecurityPDU
        """
        payload = stream.read()
        return RDPBasicSecurityPDU(header, payload)

    def parseSignedSecurity(self, stream, header):
        """
        :type stream: StringIO
        :type header: int
        :return: RDPSignedSecurityPDU
        """
        signature = stream.read(8)
        payload = stream.read()
        return RDPSignedSecurityPDU(header, signature, payload)

    def parseFIPSSecurity(self, stream, header):
        """
        :type stream: StringIO
        :type header: int
        :return: RDPFIPSSecurityPDU
        """
        headerLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPFIPSSecurityPDU(header, version, padLength, signature, payload)

    def write(self, pdu):
        """
        Encode the provided PDU to a byte stream to send to the previous layer
        :type pdu: RDPSecurityExchangePDU | RDPBasicSecurityPDU | RDPSignedSecurityPDU | RDPFIPSSecurityPDU
        :return: str
        """
        header = Uint32LE.pack(pdu.header)

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