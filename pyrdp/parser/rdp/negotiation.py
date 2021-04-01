#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Union

from pyrdp.core import Uint16LE, Uint32LE, Uint8
from pyrdp.enum import NegotiationRequestFlags, NegotiationType
from pyrdp.parser.parser import Parser
from pyrdp.pdu import NegotiationFailurePDU, NegotiationRequestPDU, NegotiationResponsePDU


class NegotiationRequestParser(Parser):
    """
    Parser for RDP negotiaton requests (Connection Request payloads).
    """
    def doParse(self, data: bytes) -> NegotiationRequestPDU:
        """
        Parse a negotiation request.
        :param data: the request data.
        """

        cookie = None

        if b"\r\n" in data:
            cookie = data[: data.index(b"\r\n")]
            data = data[data.index(b"\r\n") + 2 :]

        stream = BytesIO(data)

        if len(data) >= 8:
            type = Uint8.unpack(stream)
            requestFlags = Uint8.unpack(stream)
            requestLength = Uint16LE.unpack(stream)
            requestedProtocols = Uint32LE.unpack(stream)

            correlationFlags = None
            correlationID = None

            if requestFlags & NegotiationRequestFlags.CORRELATION_INFO_PRESENT != 0 and len(data) >= 36:
                type = Uint8.unpack(stream)
                correlationFlags = Uint8.unpack(stream)
                correlationLength = Uint16LE.unpack(stream)
                correlationID = stream.read(16)
                stream.read(16)

            return NegotiationRequestPDU(cookie, requestFlags, requestedProtocols, correlationFlags, correlationID)
        else:
            return NegotiationRequestPDU(cookie, None, None, None, None)

    def write(self, pdu):
        """
        Write a negotiation request.
        :param pdu: the request PDU.
        :type pdu: NegotiationRequestPDU
        :return: str
        """
        stream = BytesIO()

        if pdu.cookie is not None:
            stream.write(pdu.cookie + b"\r\n")

        if pdu.flags is not None and pdu.requestedProtocols is not None:
            Uint8.pack(NegotiationType.TYPE_RDP_NEG_REQ, stream)
            Uint8.pack(pdu.flags, stream)
            Uint16LE.pack(8, stream)
            Uint32LE.pack(pdu.requestedProtocols, stream)

            if pdu.correlationFlags is not None and pdu.correlationID is not None:
                Uint8.pack(NegotiationType.TYPE_RDP_CORRELATION_INFO, stream)
                Uint8.pack(pdu.correlationFlags, stream)
                Uint16LE.pack(36, stream)
                stream.write(pdu.correlationID)
                stream.write(b"\x00" * 16)

        return stream.getvalue()


class NegotiationResponseParser(Parser):
    """
    Parser for RDP negotiation responses (Connection Confirm payloads).
    """
    def doParse(self, data: bytes) -> Union[NegotiationResponsePDU, NegotiationFailurePDU]:
        """
        Parse a negotiation response.
        :param data: the response data.
        """
        stream = BytesIO(data)

        if len(data) == 8:
            type = Uint8.unpack(stream)
            flags = Uint8.unpack(stream)
            length = Uint16LE.unpack(stream)

            if type == NegotiationType.TYPE_RDP_NEG_FAILURE:
                failureCode = Uint32LE.unpack(stream)
                return NegotiationFailurePDU(type, flags, failureCode)
            else:
                selectedProtocols = Uint32LE.unpack(stream)
                return NegotiationResponsePDU(type, flags, selectedProtocols)
        else:
            return NegotiationResponsePDU(None, None, None)

    def write(self, pdu):
        """
        Write a negotiation response.
        :param pdu: the response PDU.
        :type pdu: NegotiationResponsePDU
        :return: str
        """
        stream = BytesIO()

        if pdu.flags is not None and pdu.selectedProtocols is not None:
            Uint8.pack(NegotiationType.TYPE_RDP_NEG_RSP, stream)
            Uint8.pack(pdu.flags, stream)
            Uint16LE.pack(8, stream)
            Uint32LE.pack(pdu.selectedProtocols, stream)

        return stream.getvalue()
