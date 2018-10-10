from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16LE, Uint32LE

class RDPSecurityFlags:
    SEC_EXCHANGE_PKT = 0x0001
    SEC_TRANSPORT_REQ = 0x0002
    SEC_TRANSPORT_RSP = 0x0004
    SEC_ENCRYPT = 0x0008
    SEC_RESET_SEQNO = 0x0010
    SEC_IGNORE_SEQNO = 0x0020
    SEC_INFO_PKT = 0x0040
    SEC_LICENSE_PKT = 0x0080
    SEC_LICENSE_ENCRYPT_CS = 0x0100
    SEC_LICENSE_ENCRYPT_SC = 0x0200
    SEC_REDIRECTION_PKT = 0x0400
    SEC_SECURE_CHECKSUM = 0x0800
    SEC_AUTODETECT_REQ = 0x1000
    SEC_AUTODETECT_RSP = 0x2000
    SEC_HEARTBEAT = 0x4000
    SEC_FLAGSHI_VALID = 0x8000

class RDPSecurityHeaderType:
    NONE = 0
    BASIC = 1
    SIGNED = 2
    FIPS = 3

class FIPSVersion:
    TSFIPS_VERSION1 = 1

class RDPBasicSecurityPDU:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

class RDPSignedSecurityPDU:
    def __init__(self, header, signature, payload):
        self.header = header
        self.signature = signature
        self.payload = payload

class RDPFIPSSecurityPDU:
    def __init__(self, header, version, padLength, signature, payload):
        self.header = header
        self.version = version
        self.padLength = padLength
        self.signature = signature
        self.payload = payload

class RDPSecurityExchangePDU:
    def __init__(self, header, clientRandom):
        self.header = header
        self.clientRandom = clientRandom

class RDPSecurityParser:
    def __init__(self, headerType):
        self.headerType = headerType
        
    def parse(self, data):
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
        header = self.parseBasicHeader(stream)
        payload = stream.read()
        return RDPBasicSecurityPDU(header, payload)

    def parseSignedSecurity(self, stream):
        header = self.parseBasicHeader(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPSignedSecurityPDU(header, signature, payload)
    
    def parseFIPSSecurity(self, stream):
        header = self.parseBasicHeader(stream)
        headerLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPFIPSSecurityPDU(header, version, padLength, signature, payload)

    def parseBasicHeader(self, stream):
        flags = Uint16LE.unpack(stream)
        hiFlags = Uint16LE.unpack(stream)
        return (hiFlags << 16) | flags

    def parseSecurityExchange(self, data):
        stream = StringIO(data)
        header = self.parseBasicHeader(stream)
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(header, clientRandom)



    def write(self, pdu):
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