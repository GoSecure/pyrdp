#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from binascii import hexlify
from typing import Union

from pyrdp.core import ObservedBy
from pyrdp.enum import EncryptionMethod, SecurityFlags
from pyrdp.layer.layer import IntermediateLayer, LayerObserver
from pyrdp.logging import log
from pyrdp.parser import BasicSecurityParser, ClientInfoParser, FIPSSecurityParser, SignedSecurityParser
from pyrdp.pdu import ClientInfoPDU, PDU, SecurityExchangePDU, SecurityPDU
from pyrdp.security import RC4Crypter, RC4CrypterProxy


class SecurityObserver(LayerObserver):
    def onSecurityExchangeReceived(self, pdu: SecurityExchangePDU):
        """
        Called when a Security Exchange PDU is received.
        """
        pass

    def onClientInfoReceived(self, data: bytes):
        """
        Called when client info data is received.
        """
        pass

    def onLicensingDataReceived(self, data: bytes):
        """
        Called when licensing data is received.
        """
        pass


@ObservedBy(SecurityObserver)
class SecurityLayer(IntermediateLayer):
    """
    Layer for security related traffic.
    """

    def __init__(self, parser: BasicSecurityParser):
        """
        :param parser: the parser to use for security traffic.
        """
        super().__init__(parser)
        self.clientInfoParser = ClientInfoParser()

    @staticmethod
    def create(encryptionMethod: EncryptionMethod, crypter: Union[RC4Crypter, RC4CrypterProxy]) -> 'SecurityLayer':
        """
        Create a security layer using the chosen encryption method and crypter.
        """
        if encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
            parser = SignedSecurityParser(crypter)
            return SecurityLayer(parser)
        elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
            parser = FIPSSecurityParser(crypter)
            return SecurityLayer(parser)

    def recv(self, data: bytes):
        pdu: SecurityPDU = self.mainParser.parse(data)

        try:
            self.dispatchPDU(pdu)
        except KeyboardInterrupt:
            raise
        except Exception:
            if isinstance(pdu, SecurityExchangePDU):
                log.error("Exception occurred when receiving Security Exchange. Data: %(securityExchangeData)s",
                          {"securityExchangeData": hexlify(data)})
            raise

    def dispatchPDU(self, pdu: SecurityPDU):
        """
        Send the PDU to the proper object depending on its type.
        :param pdu: the pdu.
        """
        if pdu.header & SecurityFlags.SEC_EXCHANGE_PKT != 0:
            if self.observer:
                self.observer.onSecurityExchangeReceived(pdu)
        elif pdu.header & SecurityFlags.SEC_INFO_PKT != 0:
            if self.observer:
                self.observer.onClientInfoReceived(pdu.payload)
        elif pdu.header & SecurityFlags.SEC_LICENSE_PKT != 0:
            if self.observer:
                self.observer.onLicensingDataReceived(pdu.payload)
        else:
            self.pduReceived(pdu)

    def sendBytes(self, data: bytes, header = 0):
        pdu = SecurityPDU(header, data)
        self.sendPDU(pdu)

    def sendSecurityExchange(self, clientRandom: bytes):
        """
        Send a security exchange PDU through the layer.
        :param clientRandom: the client random data.
        """
        pdu = SecurityExchangePDU(SecurityFlags.SEC_EXCHANGE_PKT, clientRandom + b"\x00" * 8)
        data = self.mainParser.writeSecurityExchange(pdu)
        self.previous.sendBytes(data)

    def sendClientInfo(self, pdu: ClientInfoPDU):
        """
        Send a client info PDU.
        """
        data = self.clientInfoParser.write(pdu)
        pdu = SecurityPDU(SecurityFlags.SEC_INFO_PKT, data)
        self.sendPDU(pdu)

    def sendLicensing(self, data: bytes):
        """
        Send raw licensing data.
        """
        pdu = SecurityPDU(SecurityFlags.SEC_LICENSE_PKT, data)
        self.sendPDU(pdu)

    def shouldForward(self, pdu: PDU) -> bool:
        return True


class TLSSecurityLayer(SecurityLayer):
    """
    Security layer used when the connection uses TLS.
    If securityHeadExpected is True, then the layer expects to receive a basic security header.
    Otherwise, the layer just forwards all the data it receives to the next layer.
    """

    def __init__(self, parser = BasicSecurityParser()):
        super().__init__(parser)
        self.securityHeaderExpected = False

    def recv(self, data: bytes):
        if not self.securityHeaderExpected:
            if self.next is not None:
                self.next.recv(data)
        else:
            SecurityLayer.recv(self, data)

    def sendBytes(self, data: bytes, header = 0):
        if not self.securityHeaderExpected:
            self.previous.sendBytes(data)
        else:
            SecurityLayer.sendBytes(self, data, header)
