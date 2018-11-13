from StringIO import StringIO

from rdpy.core import log

from rdpy.core.packing import Uint16LE, Uint8, Uint32LE
from rdpy.enum.rdp import RDPSecurityFlags, FIPSVersion
from rdpy.pdu.rdp.security import RDPSecurityPDU, RDPSecurityExchangePDU


class RDPBasicSecurityParser:
    def parse(self, data):
        stream = StringIO(data)
        header = Uint32LE.unpack(stream)

        if header & RDPSecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        payload = stream.read()
        return RDPSecurityPDU(header, payload)

    def parseSecurityExchange(self, stream, header):
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(header, clientRandom)

    def write(self, pdu):
        stream = StringIO()
        self.writeHeader(stream, pdu)
        self.writeBody(stream, pdu)
        self.writePayload(stream, pdu)
        return stream.getvalue()

    def writeSecurityExchange(self, pdu):
        stream = StringIO()
        Uint32LE.pack(RDPSecurityFlags.SEC_EXCHANGE_PKT | RDPSecurityFlags.SEC_LICENSE_ENCRYPT_SC, stream)
        Uint32LE.pack(len(pdu.clientRandom), stream)
        stream.write(pdu.clientRandom)
        return stream.getvalue()

    def writeHeader(self, stream, pdu):
        Uint32LE.pack(pdu.header, stream)

    def writeBody(self, stream, pdu):
        pass

    def writePayload(self, stream, pdu):
        stream.write(pdu.payload)



class RDPSignedSecurityParser(RDPBasicSecurityParser):
    def __init__(self, crypter):
        self.crypter = crypter

    def parse(self, data):
        stream = StringIO(data)
        header = Uint32LE.unpack(stream)

        if header & RDPSecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        signature = stream.read(8)
        payload = stream.read()

        if header & RDPSecurityFlags.SEC_ENCRYPT != 0:
            payload = self.crypter.decrypt(payload)
            self.crypter.addDecryption()

        return RDPSecurityPDU(header, payload)


    def writeHeader(self, stream, pdu):
        header = pdu.header | RDPSecurityFlags.SEC_ENCRYPT | RDPSecurityFlags.SEC_SECURE_CHECKSUM
        Uint32LE.pack(header, stream)

    def writeBody(self, stream, pdu):
        signature = self.crypter.sign(pdu.payload, True)
        stream.write(signature)

    def writePayload(self, stream, pdu):
        payload = self.crypter.encrypt(pdu.payload)
        self.crypter.addEncryption()
        stream.write(payload)



class RDPFIPSSecurityParser(RDPSignedSecurityParser):
    def __init__(self, crypter):
        RDPSignedSecurityParser.__init__(self, crypter)

    def parse(self, data):
        stream = StringIO(data)
        header = Uint32LE.unpack(stream)

        if header & RDPSecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        length = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = stream.read()

        if header & RDPSecurityFlags.SEC_ENCRYPT != 0:
            payload = self.crypter.decrypt(payload)
            self.crypter.addDecryption()

        return RDPSecurityPDU(header, payload)

    def writeBody(self, stream, pdu):
        Uint16LE.pack(0x10, stream)
        Uint8.pack(FIPSVersion.TSFIPS_VERSION1, stream)
        Uint8.pack(self.crypter.getPadLength(pdu.payload), stream)
        RDPSignedSecurityParser.writeBody(self, stream, pdu)
