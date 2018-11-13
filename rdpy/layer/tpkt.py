from rdpy.core.newlayer import Layer
from rdpy.core.packing import Uint8
from rdpy.enum.rdp import EncryptionMethod
from rdpy.parser.rdp.fastpath import RDPBasicFastPathParser, RDPSignedFastPathParser, RDPFIPSFastPathParser
from rdpy.parser.tpkt import TPKTParser
from rdpy.pdu.tpkt import TPKTPDU


def createFastPathParser(tls, encryptionMethod, crypter, mode):
    if tls:
        return RDPBasicFastPathParser(mode)
    elif encryptionMethod in [EncryptionMethod.ENCRYPTION_40BIT, EncryptionMethod.ENCRYPTION_56BIT, EncryptionMethod.ENCRYPTION_128BIT]:
        return RDPSignedFastPathParser(crypter, mode)
    elif encryptionMethod == EncryptionMethod.ENCRYPTION_FIPS:
        return RDPFIPSFastPathParser(crypter, mode)
    else:
        raise ValueError("Invalid fast-path layer mode")


class TPKTLayer(Layer):
    """
    Layer to handle TPKT-wrapped traffic
    """

    def __init__(self):
        Layer.__init__(self)
        self.buffer = ""
        self.fastPathLayer = None
        self.parsers = {
            3: TPKTParser()
        }

    def setFastPathParser(self, parser):
        self.parsers[0] = parser

    def setFastPathLayer(self, layer):
        self.fastPathLayer = layer
        layer.previous = self.previous

    def recv(self, data):
        """
        Since there can be more than one TPKT message per TCP packet, parse
        a TPKT message, handle the packet then check if we have more messages left.
        Note that TPKT reassembly (when a TPKT message is in more than one TCP packet) is not tested to be working.
        :param data: The TCP packet's payload
        :type data: str
        """
        data = self.buffer + data

        while len(data) > 0:
            header = Uint8.unpack(data[0]) & 0b00000011
            parser = self.parsers[header]

            if not parser.isCompletePDU(data):
                self.buffer = data
                data = ""
            else:
                pduLength = parser.getPDULength(data)
                pduData = data[: pduLength]

                pdu = parser.parse(pduData)
                self.pduReceived(pdu, header == 3)

                data = data[pduLength :]
                self.buffer = ""

    def send(self, data):
        """
        Wrap the data inside a TPKT message and send it to the previous layer (TCP).
        :param data: The data we wish to send in a TPKT message
        :type data: str
        """
        pdu = TPKTPDU(3, data)
        self.previous.send(self.parsers[3].write(pdu))

    def sendPDU(self, pdu):
        header = pdu.header & 3
        parser = self.parsers[header]
        data = parser.write(pdu)
        self.previous.send(data)

    def sendData(self, data):
        self.previous.send(data)

    def startTLS(self, tlsContext):
        """
        Tell the previous layer (in our case the TCP layer) to do the TLS handshake to encrypt further communications.
        :param tlsContext: Twisted TLS Context object (like DefaultOpenSSLContextFactory)
        :type tlsContext: ServerTLSContext
        """
        self.previous.startTLS(tlsContext)
