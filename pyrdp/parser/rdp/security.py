from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE, Uint8
from pyrdp.enum import FIPSVersion, SecurityFlags
from pyrdp.parser.parser import Parser
from pyrdp.pdu import SecurityExchangePDU, SecurityPDU
from pyrdp.security import RC4Crypter, RC4CrypterProxy


class BasicSecurityParser(Parser):
    """
    Base class for all security parsers.
    This class only reads a small header before the payload.
    Writing is split between 3 methods for reusability.
    """

    def parse(self, data):
        """
        Decode a security PDU from bytes.
        :type data: bytes
        :return: RDPSecurityPDU
        """
        stream = BytesIO(data)
        header = Uint32LE.unpack(stream)

        if header & SecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        payload = stream.read()
        return SecurityPDU(header, payload)

    def parseSecurityExchange(self, stream, header):
        """
        Decode a security exchange PDU.
        :type stream: BytesIO
        :type header: int
        :return: RDPSecurityExchangePDU
        """
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return SecurityExchangePDU(header, clientRandom)

    def write(self, pdu):
        """
        Encode a security PDU to bytes.
        :type pdu: SecurityPDU
        :return: str
        """
        stream = BytesIO()
        self.writeHeader(stream, pdu)
        self.writeBody(stream, pdu)
        self.writePayload(stream, pdu)
        return stream.getvalue()

    def writeSecurityExchange(self, pdu):
        """
        Encode a RDPSecurityExchangePDU to bytes.
        :type pdu: SecurityExchangePDU
        :return: str
        """
        stream = BytesIO()
        Uint32LE.pack(SecurityFlags.SEC_EXCHANGE_PKT | SecurityFlags.SEC_LICENSE_ENCRYPT_SC, stream)
        Uint32LE.pack(len(pdu.clientRandom), stream)
        stream.write(pdu.clientRandom)
        return stream.getvalue()

    def writeHeader(self, stream, pdu):
        """
        Write the PDU header.
        :type stream: BytesIO
        :type pdu: SecurityPDU
        """
        Uint32LE.pack(pdu.header, stream)

    def writeBody(self, stream, pdu):
        """
        Write the PDU body.
        :type stream: BytesIO
        :type pdu: SecurityPDU
        """
        pass

    def writePayload(self, stream, pdu):
        """
        Write the PDU payload.
        :type stream: BytesIO
        :type pdu: SecurityPDU
        """
        stream.write(pdu.payload)



class SignedSecurityParser(BasicSecurityParser):
    """
    Parser to use when standard RDP security is used.
    This class handles RC4 decryption and encryption and increments the operation count automatically.
    """

    def __init__(self, crypter):
        """
        :type crypter: RC4Crypter | RC4CrypterProxy
        """
        BasicSecurityParser.__init__(self)
        self.crypter = crypter

    def parse(self, data):
        stream = BytesIO(data)
        header = Uint32LE.unpack(stream)

        if header & SecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        signature = stream.read(8)
        payload = stream.read()

        if header & SecurityFlags.SEC_ENCRYPT != 0:
            payload = self.crypter.decrypt(payload)
            self.crypter.addDecryption()

        return SecurityPDU(header, payload)


    def writeHeader(self, stream, pdu):
        # Make sure the header contains the flags for encryption and salted signatures.
        header = pdu.header | SecurityFlags.SEC_ENCRYPT | SecurityFlags.SEC_SECURE_CHECKSUM
        Uint32LE.pack(header, stream)

    def writeBody(self, stream, pdu):
        # Write the signature before writing the payload.
        signature = self.crypter.sign(pdu.payload, True)
        stream.write(signature)

    def writePayload(self, stream, pdu):
        payload = self.crypter.encrypt(pdu.payload)
        self.crypter.addEncryption()
        stream.write(payload)



class FIPSSecurityParser(SignedSecurityParser):
    """
    Parser to use when FIPS security is used.
    Note that FIPS cryptography is not implemented yet.
    """

    def __init__(self, crypter):
        """
        :type crypter: RC4Crypter | RC4CrypterProxy
        """
        SignedSecurityParser.__init__(self, crypter)

    def parse(self, data):
        stream = BytesIO(data)
        header = Uint32LE.unpack(stream)

        if header & SecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        length = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = stream.read()

        if header & SecurityFlags.SEC_ENCRYPT != 0:
            payload = self.crypter.decrypt(payload)
            self.crypter.addDecryption()

        return SecurityPDU(header, payload)

    def writeBody(self, stream, pdu):
        Uint16LE.pack(0x10, stream)
        Uint8.pack(FIPSVersion.TSFIPS_VERSION1, stream)
        Uint8.pack(self.crypter.getPadLength(pdu.payload), stream)
        SignedSecurityParser.writeBody(self, stream, pdu)
