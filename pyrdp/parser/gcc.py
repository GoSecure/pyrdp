#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import per, Uint16BE
from pyrdp.enum import GCCPDUType
from pyrdp.exceptions import ParsingError, UnknownPDUTypeError
from pyrdp.parser.parser import Parser
from pyrdp.pdu import GCCConferenceCreateRequestPDU, GCCConferenceCreateResponsePDU, GCCPDU


class GCCParser(Parser):
    """
    Parser class to read and write GCC (T.124) PDUs.
    """

    T124_02_98_OID = (0, 0, 20, 124, 0, 1)
    H221_CLIENT_KEY = b"Duca"
    H221_SERVER_KEY = b"McDn"
    NODE_ID = 0x79f3

    def __init__(self):
        super().__init__()
        self.parsers = {
            GCCPDUType.CREATE_CONFERENCE_REQUEST: self.parseConferenceCreateRequest,
            GCCPDUType.CREATE_CONFERENCE_RESPONSE: self.parseConferenceCreateResponse,
        }

        self.writers = {
            GCCPDUType.CREATE_CONFERENCE_REQUEST: self.writeConferenceCreateRequest,
            GCCPDUType.CREATE_CONFERENCE_RESPONSE: self.writeConferenceCreateResponse,
        }

    def parse(self, data: bytes) -> GCCPDU:
        """
        Parses the raw data bytes into a GCCPDU
        :param data: PDU data.
        """
        stream = BytesIO(data)

        tag = per.readChoice(stream)

        if tag != 0:
            raise ParsingError("Expected object tag (0), got %d instead" % tag)

        oid = per.readObjectIdentifier(stream)

        if oid != GCCParser.T124_02_98_OID:
            raise ParsingError("Invalid object identifier: %r, expected %r" % (oid, GCCParser.T124_02_98_OID))

        _length = per.readLength(stream)
        header = per.readChoice(stream)

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown GCC PDU type %s" % header, header)

        pdu = self.parsers[header](stream)

        return pdu

    def parseConferenceCreateRequest(self, stream: BytesIO) -> GCCConferenceCreateRequestPDU:
        """
        Parse ConferenceCreateRequest data into a GCCPDU
        :param stream: byte stream containing the PDU data
        """
        prop = per.readSelection(stream)

        if prop != 8:
            raise ParsingError("Expected property to be 8 (conference name), got %d" % prop)

        conferenceName = per.readNumericString(stream, 1)
        stream.read(1)

        userDataCount = per.readNumberOfSet(stream)
        if userDataCount != 1:
            raise ParsingError("Expected user data count to be 1, got %d" % userDataCount)

        userDataType = per.readChoice(stream)
        if userDataType != 0xc0:
            raise ParsingError("Expected user data type to be 0xc0 (h221NonStandard), got %d" % userDataType)

        key = per.readOctetStream(stream, 4)
        if key != GCCParser.H221_CLIENT_KEY:
            raise ParsingError("Expected user data key to be %s, got %s" % (GCCParser.H221_CLIENT_KEY, key))

        payload = per.readOctetStream(stream)
        return GCCConferenceCreateRequestPDU(conferenceName, payload)

    def parseConferenceCreateResponse(self, stream: BytesIO) -> GCCConferenceCreateResponsePDU:
        """
        Parse ConferenceCreateResponse data into a GCCPDU
        :param stream: byte stream containing the PDU data
        """

        nodeID = Uint16BE.unpack(stream.read(2)) + 1001
        tag = per.readInteger(stream)
        result = per.readEnumeration(stream)

        userDataCount = per.readNumberOfSet(stream)
        if userDataCount != 1:
            raise ParsingError("Expected user data count to be 1, got %d" % userDataCount)

        userDataType = per.readChoice(stream)
        if userDataType != 0xc0:
            raise ParsingError("Expected user data type to be 0xc0 (h221NonStandard), got %d" % userDataType)

        key = per.readOctetStream(stream, 4)
        if key != GCCParser.H221_SERVER_KEY:
            raise ParsingError("Expected user data key to be %s, got %s" % (GCCParser.H221_SERVER_KEY, key))

        payload = per.readOctetStream(stream)
        return GCCConferenceCreateResponsePDU(nodeID, tag, result, payload)

    def write(self, pdu: GCCPDU) -> bytes:
        """
        Encode a GCC PDU to bytes.
        :param pdu: gcc PDU.
        """
        if pdu.header not in self.writers:
            raise UnknownPDUTypeError("Trying to write unknown GCC PDU type %s" % pdu.header, pdu.header)

        stream = BytesIO()
        stream.write(per.writeChoice(0))
        stream.write(per.writeObjectIdentifier(GCCParser.T124_02_98_OID))

        # Normally this should be len(pdu.payload) + 14, but Windows seems to always send 0x2a. This value is also
        # accepted by Wireshark.
        stream.write(per.writeLength(0x2a))
        stream.write(per.writeChoice(pdu.header))

        self.writers[pdu.header](stream, pdu)
        return stream.getvalue()

    def writeConferenceCreateRequest(self, stream: BytesIO, pdu: GCCConferenceCreateRequestPDU):
        """
        Write a GCCConferenceCreateRequestPDU to a stream.
        :param stream: byte stream to put the ConferenceCreateRequest data in.
        :param pdu: the PDU to write.
        """
        stream.write(per.writeSelection(8))
        stream.write(per.writeNumericString(pdu.conferenceName, 1))
        stream.write(per.writeEnumeration(0))
        stream.write(per.writeNumberOfSet(1))
        stream.write(per.writeChoice(0xc0))
        stream.write(per.writeOctetStream(GCCParser.H221_CLIENT_KEY, 4))
        stream.write(per.writeOctetStream(pdu.payload))

    def writeConferenceCreateResponse(self, stream: BytesIO, pdu: GCCConferenceCreateResponsePDU):
        """
        Write a GCCConferenceCreateResponsePDU to a stream.
        :param stream: byte stream to put the ConferenceCreateResponse data in.
        :param pdu: the PDU to write.
        """

        stream.write(Uint16BE.pack(GCCParser.NODE_ID - 1001))
        stream.write(per.writeInteger(1))
        stream.write(per.writeEnumeration(0))
        stream.write(per.writeNumberOfSet(1))
        stream.write(per.writeChoice(0xc0))
        stream.write(per.writeOctetStream(GCCParser.H221_SERVER_KEY, 4))
        stream.write(per.writeOctetStream(pdu.payload))
