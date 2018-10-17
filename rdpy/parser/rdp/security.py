from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint8, Uint32LE
from rdpy.enum.rdp import RDPSecurityHeaderType
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

        if self.headerType == RDPSecurityHeaderType.BASIC:
            return self.parseBasicSecurity(stream)
        elif self.headerType == RDPSecurityHeaderType.SIGNED:
            return self.parseSignedSecurity(stream)
        elif self.headerType == RDPSecurityHeaderType.FIPS:
            return self.parseFIPSSecurity(stream)
        else:
            raise Exception("Trying to parse unknown security header type")

    def parseBasicSecurity(self, stream):
        """
        :type stream: StringIO
        :return: RDPBasicSecurityPDU
        """
        flags = self.parseBasicHeader(stream)
        payload = stream.read()
        return RDPBasicSecurityPDU(flags, payload)

    def parseSignedSecurity(self, stream):
        """
        :type stream: StringIO
        :return: RDPSignedSecurityPDU
        """
        header = self.parseBasicHeader(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPSignedSecurityPDU(header, signature, payload)

    def parseFIPSSecurity(self, stream):
        """
        :type stream: StringIO
        :return: RDPFIPSSecurityPDU
        """
        header = self.parseBasicHeader(stream)
        headerLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPFIPSSecurityPDU(header, version, padLength, signature, payload)

    def parseBasicHeader(self, stream):
        """
        :type stream: StringIO
        :return: int The flags value (32 bits)
        """
        flags = Uint16LE.unpack(stream)
        hiFlags = Uint16LE.unpack(stream)
        return (hiFlags << 16) | flags

    def parseSecurityExchange(self, data):
        """
        :type data: str
        :return: RDPSecurityExchangePDU
        """
        stream = StringIO(data)
        flags = self.parseBasicHeader(stream)
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(flags, clientRandom)

    def write(self, pdu):
        """
        Encode the provided PDU to a byte stream to send to the previous layer
        :type pdu: RDPBasicSecurityPDU
        :return: str
        """
        if isinstance(pdu, RDPSecurityExchangePDU):
            return self.writeSecurityExchange(pdu)
        elif isinstance(pdu, RDPBasicSecurityPDU):
            return self.writeBasicHeader(pdu) + pdu.payload
        elif isinstance(pdu, RDPSignedSecurityPDU):
            return self.writeSignedHeader(pdu) + pdu.payload
        elif isinstance(pdu, RDPFIPSSecurityPDU):
            return self.writeFIPSHeader(pdu) + pdu.payload
        else:
            raise Exception("Trying to write unknown PDU type")

    def writeBasicHeader(self, pdu):
        return Uint16LE.pack(pdu.header & 0xffff) + Uint16LE.pack(pdu.header >> 16)

    def writeSignedHeader(self, pdu):
        return self.writeBasicHeader(pdu) + pdu.signature[: 8]

    def writeFIPSHeader(self, pdu):
        return self.writeBasicHeader(pdu) + Uint16LE.pack(0x10) + Uint8.pack(pdu.version) + Uint8.pack(pdu.padLength) + pdu.signature[: 8]

    def writeSecurityExchange(self, pdu):
        return self.writeBasicHeader(pdu) + Uint32LE.pack(len(pdu.clientRandom)) + pdu.clientRandom