from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16LE, Uint32LE, Int32LE
from rdpy.exceptions import WritingError, UnknownPDUTypeError
from rdpy.pdu.rdp.negotiation import RDPNegotiationRequestPDU, RDPNegotiationResponsePDU
from rdpy.protocol.rdp.x224 import NegociationType


class RDPNegotiationParser:
    """
    Parse the first two packets of the RDP connection sequence,
    where the security protocol is chosen.
    """

    def __init__(self):
        self.writers = {
            NegociationType.TYPE_RDP_NEG_REQ: self.writeNegotiationRequestPDU,
            NegociationType.TYPE_RDP_NEG_RSP: self.writeNegotiationResponsePDU,
        }


    def parse(self, data):
        """
        Parse RDP Negotiation Request packet. Throws Exceptions if packet is malformed.
        :param data: The bytes of the RDP Negotiation Request packet.
        :return: A RDPNegotiationRequestPDU
        """
        cookie = ""

        if "\r\n" in data:
            cookie = data[: data.index("\r\n")]
            data = data[data.index("\r\n") + 2 :]

        if len(data) == 8:
            stream = StringIO(data)
            type = Uint8.unpack(stream)
            if type == NegociationType.TYPE_RDP_NEG_REQ:
                return self.parseNegotiationRequest(stream, cookie)
            elif type == NegociationType.TYPE_RDP_NEG_RSP:
                return self.parseNegotiationResponse(stream)
            else:
                raise UnknownPDUTypeError("Trying to parse unknown negotiation PDU: %d" % type, type)

    def parseNegotiationRequest(self, stream, cookie):
        flags = Uint8.unpack(stream)
        length = Uint16LE.unpack(stream)
        requestedProtocols = Uint32LE.unpack(stream)
        return RDPNegotiationRequestPDU(cookie, flags, requestedProtocols)

    def parseNegotiationResponse(self, stream):
        flags = Uint8.unpack(stream)
        length = Uint16LE.unpack(stream)
        requestedProtocols = Uint32LE.unpack(stream)
        return RDPNegotiationResponsePDU(flags, requestedProtocols)

    def write(self, pdu):
        """
        :param pdu: The PDU to write
        :return: A StringIO of the bytes of the given PDU
        """
        if pdu.packetType in self.writers.keys():
            return self.writers[pdu.packetType](pdu)
        else:
            raise WritingError("Trying to write invalid packet type %d" % pdu.packetType)

    def writeNegotiationRequestPDU(self, pdu):
        """
        :type pdu: RDPNegotiationRequestPDU
        """
        stream = StringIO()

        if pdu.cookie != "":
            stream.write(pdu.cookie + "\r\n")

        Uint8.pack(pdu.packetType, stream)
        Uint8.pack(pdu.flags, stream)
        Uint16LE.pack(8, stream)
        Uint32LE.pack(pdu.requestedProtocols, stream)
        return stream.getvalue()

    def writeNegotiationResponsePDU(self, pdu):
        """
        :type pdu: RDPNegotiationResponsePDU
        """
        stream = StringIO()
        stream.write(Uint8.pack(pdu.packetType))
        stream.write(Uint8.pack(pdu.flags))
        stream.write(Uint8.pack(8))  # Length
        stream.write(Uint8.pack(0))  # Empty byte?
        stream.write(Int32LE.pack(pdu.selectedProtocols))
        return stream.getvalue()