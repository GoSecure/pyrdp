from collections import namedtuple

from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPSecurityHeaderType, RDPSecurityFlags, FIPSVersion, EncryptionMethod
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.security import RDPSecurityParser
from rdpy.pdu.rdp.security import RDPSecurityExchangePDU, RDPBasicSecurityPDU, RDPSignedSecurityPDU, RDPFIPSSecurityPDU


def createNonTLSSecurityLayer(encryptionMethod, crypter):
    if encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
        return SignedSecurityLayer(crypter)
    elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
        return FIPSSecurityLayer(crypter)


class RDPSecurityObserver(LayerObserver):
    def onSecurityExchangeReceived(self, pdu):
        """
        Called when a Security Exchange PDU is received.
        """
        pass

    def onClientInfoReceived(self, pdu):
        """
        Called when a Client Info PDU is received.
        """
        pass



@ObservedBy(RDPSecurityObserver)
class RDPSecurityLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.licensing = None
        self.clientInfoParser = RDPClientInfoParser()

    def setLicensingLayer(self, licensing):
        securityProxy = namedtuple("SecurityProxy", "send")(send = self.sendLicensing)

        self.licensing = licensing
        self.licensing.previous = securityProxy

    def recv(self, data):
        raise NotImplementedError("recv must be overridden")

    def dispatchPDU(self, pdu):
        if pdu.header & RDPSecurityFlags.SEC_EXCHANGE_PKT != 0:
            self.observer.onSecurityExchangeReceived(pdu)
        elif pdu.header & RDPSecurityFlags.SEC_INFO_PKT != 0:
            clientInfo = self.clientInfoParser.parse(pdu.payload)
            self.observer.onClientInfoReceived(clientInfo)
        elif pdu.header & RDPSecurityFlags.SEC_LICENSE_PKT != 0:
            self.licensing.recv(pdu.payload)
        else:
            self.pduReceived(pdu, True)

    def sendSecurityExchange(self, clientRandom):
        pdu = RDPSecurityExchangePDU(RDPSecurityFlags.SEC_EXCHANGE_PKT | RDPSecurityFlags.SEC_LICENSE_ENCRYPT_SC, clientRandom + "\x00" * 8)
        self.previous.send(self.securityParser.write(pdu))

    def send(self, data, header = 0):
        raise NotImplementedError("send must be overridden")

    def sendClientInfo(self, pdu):
        raise NotImplementedError("sendClientInfo must be overridden")

    def sendLicensing(self, data):
        raise NotImplementedError("sendLicensing must be overridden")



class TLSSecurityLayer(RDPSecurityLayer):
    def __init__(self):
        RDPSecurityLayer.__init__(self)
        self.securityParser = RDPSecurityParser(RDPSecurityHeaderType.NONE)
        self.securityHeaderExpected = False

    def recv(self, data):
        if not self.securityHeaderExpected:
            self.next.recv(data)
        else:
            pdu = self.securityParser.parse(data)
            self.dispatchPDU(pdu)

    def send(self, data, header = 0):
        self.previous.send(data)

    def sendClientInfo(self, pdu):
        data = self.clientInfoParser.write(pdu)
        pdu = RDPBasicSecurityPDU(RDPSecurityFlags.SEC_INFO_PKT, data)
        self.previous.send(self.securityParser.write(pdu))

    def sendLicensing(self, data):
        pdu = RDPBasicSecurityPDU(RDPSecurityFlags.SEC_LICENSE_PKT, data)
        self.previous.send(self.securityParser.write(pdu))



class NonTLSSecurityLayer(RDPSecurityLayer):
    def __init__(self, headerType, crypter):
        RDPSecurityLayer.__init__(self)
        self.crypter = crypter
        self.securityParser = RDPSecurityParser(headerType)

    def recv(self, data):
        pdu = self.securityParser.parse(data)

        if pdu.header & RDPSecurityFlags.SEC_ENCRYPT != 0:
            pdu.payload = self.crypter.decrypt(pdu.payload)
            self.crypter.addDecryption()

        self.dispatchPDU(pdu)

    def send(self, data, header = 0):
        header |= RDPSecurityFlags.SEC_ENCRYPT
        ciphertext = self.crypter.encrypt(data)

        self.sendEncrypted(data, ciphertext, header)
        self.crypter.addEncryption()

    def sendClientInfo(self, pdu):
        data = self.clientInfoParser.write(pdu)
        self.send(data, RDPSecurityFlags.SEC_INFO_PKT)

    def sendLicensing(self, data):
        self.send(data, RDPSecurityFlags.SEC_LICENSE_PKT)

    def sendEncrypted(self, plaintext, ciphertext, header):
        raise NotImplementedError("sendEncrypted must be overridden")


class BasicSecurityLayer(NonTLSSecurityLayer):
    def __init__(self, crypter):
        NonTLSSecurityLayer.__init__(self, RDPSecurityHeaderType.BASIC, crypter)

    def sendEncrypted(self, plaintext, ciphertext, header):
        pdu = RDPBasicSecurityPDU(header, ciphertext)
        self.previous.send(self.securityParser.write(pdu))


class SignedSecurityLayer(NonTLSSecurityLayer):
    def __init__(self, crypter):
        NonTLSSecurityLayer.__init__(self, RDPSecurityHeaderType.SIGNED, crypter)

    def sendEncrypted(self, plaintext, ciphertext, header):
        header |= RDPSecurityFlags.SEC_SECURE_CHECKSUM
        signature = self.crypter.sign(plaintext, True)

        pdu = RDPSignedSecurityPDU(header, signature, ciphertext)
        self.previous.send(self.securityParser.write(pdu))


class FIPSSecurityLayer(NonTLSSecurityLayer):
    def __init__(self, crypter):
        NonTLSSecurityLayer.__init__(self, RDPSecurityHeaderType.FIPS, crypter)

    def sendEncrypted(self, plaintext, ciphertext, header):
        header |= RDPSecurityFlags.SEC_SECURE_CHECKSUM
        signature = self.crypter.sign(plaintext, True)
        padLength = self.crypter.getPadLength(plaintext)
        pdu = RDPFIPSSecurityPDU(header, FIPSVersion.TSFIPS_VERSION1, padLength, signature, ciphertext)
        self.previous.send(self.securityParser.write(pdu))
