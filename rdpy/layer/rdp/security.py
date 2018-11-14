from collections import namedtuple

from rdpy.core import log

from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.enum.rdp import RDPSecurityFlags, EncryptionMethod
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.security import RDPBasicSecurityParser, RDPSignedSecurityParser, RDPFIPSSecurityParser
from rdpy.pdu.rdp.security import RDPSecurityExchangePDU, \
    RDPSecurityPDU


def createNonTLSSecurityLayer(encryptionMethod, crypter):
    if encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
        parser = RDPSignedSecurityParser(crypter)
        return RDPSecurityLayer(parser)
    elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
        parser = RDPFIPSSecurityParser(crypter)
        return RDPSecurityLayer(parser)



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
    def __init__(self, parser):
        Layer.__init__(self)
        self.securityParser = parser
        self.licensing = None
        self.clientInfoParser = RDPClientInfoParser()

    def setLicensingLayer(self, licensing):
        securityProxy = namedtuple("SecurityProxy", "send")(send = self.sendLicensing)

        self.licensing = licensing
        self.licensing.previous = securityProxy

    def recv(self, data):
        pdu = self.securityParser.parse(data)
        try:
            self.dispatchPDU(pdu)
        except KeyboardInterrupt:
            raise
        except Exception:
            log.error("Exception occurred when receiving: %s" % pdu.payload.encode("hex"))
            raise

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

    def send(self, data, header = 0):
        pdu = RDPSecurityPDU(header, data)
        data = self.securityParser.write(pdu)
        self.previous.send(data)

    def sendSecurityExchange(self, clientRandom):
        pdu = RDPSecurityExchangePDU(RDPSecurityFlags.SEC_EXCHANGE_PKT, clientRandom + "\x00" * 8)
        data = self.securityParser.writeSecurityExchange(pdu)
        self.previous.send(data)

    def sendClientInfo(self, pdu):
        data = self.clientInfoParser.write(pdu)
        pdu = RDPSecurityPDU(RDPSecurityFlags.SEC_INFO_PKT, data)
        data = self.securityParser.write(pdu)
        self.previous.send(data)

    def sendLicensing(self, data):
        pdu = RDPSecurityPDU(RDPSecurityFlags.SEC_LICENSE_PKT, data)
        self.previous.send(self.securityParser.write(pdu))



class TLSSecurityLayer(RDPSecurityLayer):
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

