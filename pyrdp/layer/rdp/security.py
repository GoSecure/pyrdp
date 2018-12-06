from binascii import hexlify

from pyrdp.logging import log
from pyrdp.core.subject import ObservedBy
from pyrdp.crypto.crypto import RC4Crypter
from pyrdp.enum.rdp import RDPSecurityFlags, EncryptionMethod
from pyrdp.layer.layer import Layer, LayerObserver
from pyrdp.parser.parser import Parser
from pyrdp.parser.rdp.client_info import RDPClientInfoParser
from pyrdp.parser.rdp.security import RDPBasicSecurityParser, RDPSignedSecurityParser, RDPFIPSSecurityParser
from pyrdp.pdu.rdp.client_info import RDPClientInfoPDU
from pyrdp.pdu.rdp.security import RDPSecurityExchangePDU, \
    RDPSecurityPDU


class RDPSecurityObserver(LayerObserver):
    def onSecurityExchangeReceived(self, pdu):
        """
        Called when a Security Exchange PDU is received.
        :type pdu: RDPSecurityExchangePDU
        """
        pass

    def onClientInfoReceived(self, data):
        """
        Called when client info data is received.
        :type data: bytes
        """
        pass

    def onLicensingDataReceived(self, data):
        """
        Called when licensing data is received.
        :type data: bytes
        """
        pass


@ObservedBy(RDPSecurityObserver)
class RDPSecurityLayer(Layer):
    """
    Layer for security related traffic.
    """

    def __init__(self, parser: RDPBasicSecurityParser):
        """
        :param parser: the parser to use for security traffic.
        :type parser: Parser
        """
        Layer.__init__(self, parser, hasNext=True)
        self.mainParser = parser
        self.clientInfoParser = RDPClientInfoParser()

    @staticmethod
    def create(encryptionMethod, crypter):
        """
        Create a security layer using the chosen encryption method and crypter.
        :type encryptionMethod: EncryptionMethod
        :type crypter: RC4Crypter | RC4CrypterProxy
        :return: RDPSecurityLayer
        """
        if encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
            parser = RDPSignedSecurityParser(crypter)
            return RDPSecurityLayer(parser)
        elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
            parser = RDPFIPSSecurityParser(crypter)
            return RDPSecurityLayer(parser)

    def recv(self, data):
        pdu = self.mainParser.parse(data)
        try:
            self.dispatchPDU(pdu)
        except KeyboardInterrupt:
            raise
        except Exception:
            if isinstance(pdu, RDPSecurityExchangePDU):
                log.error("Exception occurred when receiving Security Exchange. Data: %(securityExchangeData)s",
                          {"securityExchangeData": hexlify(data)})
            else:
                log.error("Exception occurred when receiving: %(data)s", {"data": hexlify(pdu.payload).decode()})
            raise

    def dispatchPDU(self, pdu):
        """
        Send the PDU to the proper object depending on its type.
        :param pdu: the pdu.
        :type pdu: PDU.
        """
        if pdu.header & RDPSecurityFlags.SEC_EXCHANGE_PKT != 0:
            if self.observer:
                self.observer.onSecurityExchangeReceived(pdu)
        elif pdu.header & RDPSecurityFlags.SEC_INFO_PKT != 0:
            if self.observer:
                self.observer.onClientInfoReceived(pdu.payload)
        elif pdu.header & RDPSecurityFlags.SEC_LICENSE_PKT != 0:
            if self.observer:
                self.observer.onLicensingDataReceived(pdu.payload)
        else:
            self.pduReceived(pdu, self.hasNext)

    def send(self, data: bytes, header=0):
        pdu = RDPSecurityPDU(header, data)
        data = self.mainParser.write(pdu)
        self.previous.send(data)

    def sendSecurityExchange(self, clientRandom):
        """
        Send a security exchange PDU through the layer.
        :param clientRandom: the client random data.
        :type clientRandom: bytes
        """
        pdu = RDPSecurityExchangePDU(RDPSecurityFlags.SEC_EXCHANGE_PKT, clientRandom + b"\x00" * 8)
        data = self.mainParser.writeSecurityExchange(pdu)
        self.previous.send(data)

    def sendClientInfo(self, pdu):
        """
        Send a client info PDU.
        :type pdu: RDPClientInfoPDU
        """
        data = self.clientInfoParser.write(pdu)
        pdu = RDPSecurityPDU(RDPSecurityFlags.SEC_INFO_PKT, data)
        data = self.mainParser.write(pdu)
        self.previous.send(data)

    def sendLicensing(self, data):
        """
        Send raw licensing data.
        :type data: bytes
        """
        pdu = RDPSecurityPDU(RDPSecurityFlags.SEC_LICENSE_PKT, data)
        self.previous.send(self.mainParser.write(pdu))


class TLSSecurityLayer(RDPSecurityLayer):
    """
    Security layer used when the connection uses TLS.
    If securityHeadExpected is True, then the layer expects to receive a basic security header.
    Otherwise, the layer just forwards all the data it receives to the next layer.
    """

    def __init__(self):
        RDPSecurityLayer.__init__(self, RDPBasicSecurityParser())
        self.securityHeaderExpected = False

    def recv(self, data):
        if not self.securityHeaderExpected:
            self.next.recv(data)
        else:
            RDPSecurityLayer.recv(self, data)

    def send(self, data, header = 0):
        if not self.securityHeaderExpected:
            self.previous.send(data)
        else:
            RDPSecurityLayer.send(self, data, header)
