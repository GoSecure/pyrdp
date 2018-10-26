from rdpy.core.newlayer import Layer
from rdpy.enum.rdp import EncryptionMethod
from rdpy.parser.rdp.fastpath import RDPBasicFastPathParser, RDPSignedFastPathParser, RDPFIPSFastPathParser


def createFastPathLayer(tls, encryptionMethod, crypter, mode):
    if tls:
        parser = RDPBasicFastPathParser(mode)
    elif encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
        parser = RDPSignedFastPathParser(crypter, mode)
    elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
        parser = RDPFIPSFastPathParser(crypter, mode)
    else:
        raise ValueError("Invalid fast-path layer mode")

    return FastPathLayer(parser)


class FastPathLayer(Layer):
    def __init__(self, parser):
        Layer.__init__(self)
        self.parser = parser
        self.buffer = ""

    def sendPDU(self, pdu):
        self.previous.send(self.parser.write(pdu))

    def recv(self, data):
        data = self.buffer + data

        while len(data) > 0:
            if not self.parser.isCompletePDU(data):
                self.buffer = data
                data = ""
            else:
                length = self.parser.getPDULength(data)
                pdu = self.parser.parse(data[: length])
                self.pduReceived(pdu, True)
                data = data[length :]
