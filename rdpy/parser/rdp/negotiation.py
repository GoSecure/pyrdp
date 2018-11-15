from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16LE, Uint32LE
from rdpy.enum.negotiation import NegotiationRequestFlags, NegotiationType
from rdpy.parser.parser import Parser
from rdpy.pdu.rdp.negotiation import RDPNegotiationRequestPDU, RDPNegotiationResponsePDU


class RDPNegotiationRequestParser(Parser):
    """
    Parser for RDP negotiaton requests (Connection Request payloads).
    """
    def parse(self, data):
        """
        Parse a negotiation request.
        :param data: the request data.
        :type data: str
        :return: RDPNegotiationRequestPDU
        """

        cookie = None

        if "\r\n" in data:
            cookie = data[: data.index("\r\n")]
            data = data[data.index("\r\n") + 2 :]

        stream = StringIO(data)

        if len(data) >= 8:
            type = Uint8.unpack(stream)
            requestFlags = Uint8.unpack(stream)
            requestLength = Uint16LE.unpack(stream)
            requestedProtocols = Uint32LE.unpack(stream)

            correlationFlags = None
            correlationID = None
            reserved = None

            if requestFlags & NegotiationRequestFlags.CORRELATION_INFO_PRESENT != 0 and len(data) >= 36:
                type = Uint8.unpack(stream)
                correlationFlags = Uint8.unpack(stream)
                correlationLength = Uint16LE.unpack(stream)
                correlationID = stream.read(16)
                reserved = stream.read(16)

            return RDPNegotiationRequestPDU(cookie, requestFlags, requestedProtocols, correlationFlags, correlationID, reserved)
        else:
            return RDPNegotiationRequestPDU(cookie, None, None, None, None, None)

    def write(self, pdu):
        """
        Write a negotiation request.
        :param pdu: the request PDU.
        :type pdu: RDPNegotiationRequestPDU
        :return: str
        """
        stream = StringIO()

        if pdu.cookie is not None:
            stream.write(pdu.cookie + "\r\n")

        if pdu.flags is not None and pdu.requestedProtocols is not None:
            Uint8.pack(NegotiationType.TYPE_RDP_NEG_REQ, stream)
            Uint8.pack(pdu.flags, stream)
            Uint16LE.pack(8, stream)
            Uint32LE.pack(pdu.requestedProtocols, stream)

            if pdu.correlationFlags is not None and pdu.correlationID is not None and pdu.reserved is not None:
                Uint8.pack(NegotiationType.TYPE_RDP_CORRELATION_INFO, stream)
                Uint8.pack(pdu.correlationFlags, stream)
                Uint16LE.pack(36, stream)
                stream.write(pdu.correlationID)
                stream.write(pdu.reserved)

        return stream.getvalue()


class RDPNegotiationResponseParser(Parser):
    """
    Parser for RDP negotiation responses (Connection Confirm payloads).
    """
    def parse(self, data):
        """
        Parse a negotiation response.
        :param data: the response data.
        :type data: str
        :return: RDPNegotiationResponsePDU
        """
        stream = StringIO(data)

        if len(data) == 8:
            type = Uint8.unpack(stream)
            flags = Uint8.unpack(stream)
            length = Uint16LE.unpack(stream)
            selectedProtocols = Uint32LE.unpack(stream)
            return RDPNegotiationResponsePDU(flags, selectedProtocols)
        else:
            return RDPNegotiationResponsePDU(None, None)

    def write(self, pdu):
        """
        Write a negotiation response.
        :param pdu: the response PDU.
        :type pdu: RDPNegotiationResponsePDU
        :return: str
        """
        stream = StringIO()

        if pdu.flags is not None and pdu.selectedProtocols is not None:
            Uint8.pack(NegotiationType.TYPE_RDP_NEG_RSP, stream)
            Uint8.pack(pdu.flags, stream)
            Uint16LE.pack(8, stream)
            Uint32LE.pack(pdu.selectedProtocols, stream)

        return stream.getvalue()