from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16LE, Uint32LE, Int32LE
from rdpy.enum.rdp import NegotiationProtocols
from rdpy.exceptions import WritingError
from rdpy.pdu.rdp.negotiation import RDPNegotiationRequestPDU
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
        flags = 0
        requested_protocols = NegotiationProtocols.NONE

        if "\r\n" in data:
            cookie = data[: data.index("\r\n")]
            data = data[data.index("\r\n") + 2 :]

        if len(data) == 8:
            type = Uint8.unpack(data[0])
            flags = Uint8.unpack(data[1])
            length = Uint16LE.unpack(data[2 : 4])
            requested_protocols = Uint32LE.unpack(data[4 : 8])

        return RDPNegotiationRequestPDU(cookie, flags, requested_protocols)

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
        stream.write(Int32LE.pack(pdu.selected_protocol))
        return stream.getvalue()