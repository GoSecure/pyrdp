from rdpy.core import log

from rdpy.core.newlayer import Layer
from rdpy.enum.rdp import RDPSecurityFlags, RDPSecurityHeaderType, FIPSVersion
from rdpy.parser.rdp import RDPSecurityParser, RDPLicensingParser, RDPClientConnectionParser, RDPServerConnectionParser
from rdpy.pdu.rdp.security import RDPSecurityExchangePDU, RDPBasicSecurityPDU, RDPSignedSecurityPDU, RDPFIPSSecurityPDU


class RDPClientConnectionLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.clientRDP = RDPClientConnectionParser()
        self.serverRDP = RDPServerConnectionParser()

    def recv(self, data):
        pdu = self.serverRDP.parse(data)
        self.pduReceived(pdu, True)

    def send(self, pdu):
        self.previous.send(self.clientRDP.write(pdu))


class IOChannel(Layer):
    def __init__(self, security):
        Layer.__init__(self)
        self.security = security

    def recv(self, data):
        log.info("Security Exchange result: %s" % data.encode('hex'))
        pass

class RDPSecurityLayer(Layer):
    # Header type used for Client Info and Licensing PDUs if no encryption is used
    DEFAULT_HEADER_TYPE = RDPSecurityHeaderType.BASIC

    def __init__(self, headerType, crypter):
        Layer.__init__(self)
        self.headerType = headerType
        self.crypter = crypter
        self.licensing = RDPLicensingLayer()
        self.parser = RDPSecurityParser(headerType)

    def recv(self, data):
        if self.headerType == RDPSecurityHeaderType.NONE:
            self.next.recv(data)
        else:
            pdu = self.parser.parse(data)

            if pdu.header & RDPSecurityFlags.SEC_ENCRYPT != 0:
                pdu.payload = self.crypter.decrypt(pdu.payload)
                self.crypter.addDecryption()

            if pdu.header & RDPSecurityFlags.SEC_INFO_PKT != 0:
                self.observer.onClientInfoReceived(pdu.payload)
            elif pdu.header & RDPSecurityFlags.SEC_LICENSE_PKT != 0:
                self.licensing.recv(pdu.payload)
            else:
                self.pduReceived(pdu, pdu.header & RDPSecurityFlags.SEC_INFO_PKT == 0)

    def send(self, data, isLicensing = False):
        encrypted = self.headerType not in [RDPSecurityHeaderType.NONE, RDPSecurityHeaderType.BASIC]
        flags = 0
        if encrypted:
            flags |= RDPSecurityFlags.SEC_ENCRYPT
        if isLicensing:
            self.sendLicensingData(data)
        else:
            self.sendWithHeader(data, self.headerType, flags)

    def sendSecurityExchange(self, clientRandom):
        pdu = RDPSecurityExchangePDU(RDPSecurityFlags.SEC_EXCHANGE_PKT | RDPSecurityFlags.SEC_LICENSE_ENCRYPT_SC, clientRandom + "\x00" * 8)
        self.previous.send(self.parser.writeSecurityExchange(pdu))

    def sendClientInfo(self, data):
        header = RDPSecurityFlags.SEC_INFO_PKT

        if self.headerType == RDPSecurityHeaderType.NONE:
            self.sendWithHeader(data, RDPSecurityLayer.DEFAULT_HEADER_TYPE, header)
        else:
            self.sendWithHeader(data, self.headerType, header | RDPSecurityFlags.SEC_ENCRYPT)

    def sendLicensingData(self, data):
        header = RDPSecurityFlags.SEC_LICENSE_PKT

        if self.headerType in [RDPSecurityHeaderType.NONE, RDPSecurityHeaderType.BASIC]:
            self.sendWithHeader(data, RDPSecurityLayer.DEFAULT_HEADER_TYPE, header)
        else:
            self.sendWithHeader(data, self.headerType, header | RDPSecurityFlags.SEC_ENCRYPT)

    def sendWithHeader(self, data, headerType, header):
        if headerType == RDPSecurityHeaderType.NONE:
            self.previous.send(data)
            return

        if headerType == RDPSecurityHeaderType.BASIC:
            self.sendBasicSecurity(data, header)
        elif headerType == RDPSecurityHeaderType.SIGNED:
            self.sendSignedSecurity(data, header)
        elif headerType == RDPSecurityHeaderType.FIPS:
            self.sendFIPSSecurity(data, header)
        else:
            raise Exception("Unknown security header type")

    def sendBasicSecurity(self, data, header):
        if header & RDPSecurityFlags.SEC_ENCRYPT != 0:
            data = self.crypter.encrypt(data)
            self.crypter.addEncryption()

        pdu = RDPBasicSecurityPDU(header, data)
        self.previous.send(self.parser.write(pdu))

    def sendSignedSecurity(self, data, header):
        header |= RDPSecurityFlags.SEC_SECURE_CHECKSUM
        signature = self.crypter.sign(data, True)
        data = self.crypter.encrypt(data)
        self.crypter.addEncryption()

        pdu = RDPSignedSecurityPDU(header, signature, data)
        self.previous.send(self.parser.write(pdu))

    def sendFIPSSecurity(self, data, header):
        header |= RDPSecurityFlags.SEC_SECURE_CHECKSUM
        padLength = self.crypter.getPadLength(data)
        signature = self.crypter.sign(data, True)
        data = self.crypter.encrypt(data)
        self.crypter.addEncryption()

        pdu = RDPFIPSSecurityPDU(header, FIPSVersion.TSFIPS_VERSION1, padLength, signature, data)
        self.previous.send(self.parser.write(pdu))


class RDPLicensingLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.parser = RDPLicensingParser()

    def recv(self, data):
        pdu = self.parser.parse(data)
        self.pduReceived(pdu, False)