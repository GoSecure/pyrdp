from io import BytesIO

from pyrdp.core.packing import Uint16LE, Uint8, Uint32LE
from pyrdp.enum import RDPSecurityFlags, FIPSVersion
from pyrdp.parser.parser import Parser
from pyrdp.pdu import RDPSecurityPDU, RDPSecurityExchangePDU
from pyrdp.security import RC4Crypter, RC4CrypterProxy


class RDPBasicSecurityParser(Parser):
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

        if header & RDPSecurityFlags.SEC_EXCHANGE_PKT != 0:
            return self.parseSecurityExchange(stream, header)

        payload = stream.read()
        return RDPSecurityPDU(header, payload)

    def parseSecurityExchange(self, stream, header):
        """
        Decode a security exchange PDU.
        :type stream: BytesIO
        :type header: int
        :return: RDPSecurityExchangePDU
        """
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(header, clientRandom)

    def write(self, pdu):
        """
        Encode a security PDU to bytes.
        :type pdu: RDPSecurityPDU
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
        :type pdu: RDPSecurityExchangePDU
        :return: str
        """
        stream = BytesIO()
        Uint32LE.pack(RDPSecurityFlags.SEC_EXCHANGE_PKT | RDPSecurityFlags.SEC_LICENSE_ENCRYPT_SC, stream)
        Uint32LE.pack(len(pdu.clientRandom), stream)
        stream.write(pdu.clientRandom)
        return stream.getvalue()

    def writeHeader(self, stream, pdu):
        """
        Write the PDU header.
        :type stream: BytesIO
        :type pdu: RDPSecurityPDU
        """
        Uint32LE.pack(pdu.header, stream)

    def writeBody(self, stream, pdu):
        """
        Write the PDU body.
        :type stream: BytesIO
        :type pdu: RDPSecurityPDU
        """
        pass

    def writePayload(self, stream, pdu):
        """
        Write the PDU payload.
        :type stream: BytesIO
        :type pdu: RDPSecurityPDU
        """
        stream.write(pdu.payload)



class RDPSignedSecurityParser(RDPBasicSecurityParser):
    """
    Parser to use when standard RDP security is used.
    This class handles RC4 decryption and encryption and increments the operation count automatically.
    """

    def __init__(self, crypter):
        """
        :type crypter: RC4Crypter | RC4CrypterProxy
        """
        RDPBasicSecurityParser.__init__(self)
        self.crypter = crypter

    def parse(self, data):
        stream = BytesIO(data)
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
        # Make sure the header contains the flags for encryption and salted signatures.
        header = pdu.header | RDPSecurityFlags.SEC_ENCRYPT | RDPSecurityFlags.SEC_SECURE_CHECKSUM
        Uint32LE.pack(header, stream)

    def writeBody(self, stream, pdu):
        # Write the signature before writing the payload.
        signature = self.crypter.sign(pdu.payload, True)
        stream.write(signature)

    def writePayload(self, stream, pdu):
        payload = self.crypter.encrypt(pdu.payload)
        self.crypter.addEncryption()
        stream.write(payload)



class RDPFIPSSecurityParser(RDPSignedSecurityParser):
    """
    Parser to use when FIPS security is used.
    Note that FIPS cryptography is not implemented yet.
    """

    def __init__(self, crypter):
        """
        :type crypter: RC4Crypter | RC4CrypterProxy
        """
        RDPSignedSecurityParser.__init__(self, crypter)

    def parse(self, data):
        stream = BytesIO(data)
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
