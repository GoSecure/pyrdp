from StringIO import StringIO

from rdpy.core import per
from rdpy.core.packing import Uint16BE
from rdpy.enum.gcc import GCCPDUType
from rdpy.pdu.gcc import GCCConferenceCreateRequestPDU, GCCConferenceCreateResponsePDU


class GCCParser:
    """
    Parser class to read and write GCC (T.124) PDUs.
    """

    T124_02_98_OID = (0, 0, 20, 124, 0, 1)
    H221_CLIENT_KEY = "Duca"
    H221_SERVER_KEY = "McDn"
    NODE_ID = 0x79f3

    def __init__(self):
        self.parsers = {
            GCCPDUType.CREATE_CONFERENCE_REQUEST: self.parseConferenceCreateRequest,
            GCCPDUType.CREATE_CONFERENCE_RESPONSE: self.parseConferenceCreateResponse,
        }

        self.writers = {
            GCCPDUType.CREATE_CONFERENCE_REQUEST: self.writeConferenceCreateRequest,
            GCCPDUType.CREATE_CONFERENCE_RESPONSE: self.writeConferenceCreateResponse,
        }

    def parse(self, data):
        """
        Parses the raw data bytes into a GCCPDU
        :type data: str
        :return: GCCPDU
        """
        stream = StringIO(data)

        tag = per.readChoice(stream)

        if tag != 0:
            raise Exception("Expected object tag (0), got %d instead" % tag)

        oid = per.readObjectIdentifier(stream)

        if oid != GCCParser.T124_02_98_OID:
            raise Exception("Invalid object identifier: %r, expected %r" % (oid, GCCParser.T124_02_98_OID))

        length = per.readLength(stream)
        header = per.readChoice(stream)

        if header not in self.parsers:
            raise Exception("Trying to parse unknown GCC PDU type %d" % header)

        pdu = self.parsers[header](stream)

        return pdu

    def parseConferenceCreateRequest(self, stream):
        """
        Parse ConferenceCreateRequest data into a GCCPDU
        :param stream: byte stream containing the PDU data
        :type stream: StringIO
        :return: GCCConferenceCreateRequestPDU
        """
        property = per.readSelection(stream)
        if property != 8:
            raise Exception("Expected property to be 8 (conference name), got %d" % property)

        conferenceName = per.readNumericString(stream, 1)
        padding = stream.read(1)

        userDataCount = per.readNumberOfSet(stream)
        if userDataCount != 1:
            raise Exception("Expected user data count to be 1, got %d" % userDataCount)

        userDataType = per.readChoice(stream)
        if userDataType != 0xc0:
            raise Exception("Expected user data type to be 0xc0 (h221NonStandard), got %d" % userDataType)

        key = per.readOctetStream(stream, 4)
        if key != GCCParser.H221_CLIENT_KEY:
            raise Exception("Expected user data key to be %s, got %s" % (GCCParser.H221_CLIENT_KEY, key))

        payload = per.readOctetStream(stream)
        return GCCConferenceCreateRequestPDU(conferenceName, payload)

    def parseConferenceCreateResponse(self, stream):
        """
        Parse ConferenceCreateResponse data into a GCCPDU
        :param stream: byte stream containing the PDU data
        :type stream: StringIO
        :return: GCCConferenceCreateResponsePDU
        """

        nodeID = Uint16BE.unpack(stream.read(2)) + 1001
        tag = per.readInteger(stream)
        result = per.readEnumeration(stream)

        userDataCount = per.readNumberOfSet(stream)
        if userDataCount != 1:
            raise Exception("Expected user data count to be 1, got %d" % userDataCount)

        userDataType = per.readChoice(stream)
        if userDataType != 0xc0:
            raise Exception("Expected user data type to be 0xc0 (h221NonStandard), got %d" % userDataType)

        key = per.readOctetStream(stream, 4)
        if key != GCCParser.H221_SERVER_KEY:
            raise Exception("Expected user data key to be %s, got %s" % (GCCParser.H221_SERVER_KEY, key))

        payload = per.readOctetStream(stream)
        return GCCConferenceCreateResponsePDU(nodeID, tag, result, payload)

    def write(self, pdu):
        if pdu.header not in self.writers:
            raise Exception("Trying to write unknown GCC PDU type %d" % pdu.header)

        stream = StringIO()
        stream.write(per.writeChoice(0))
        stream.write(per.writeObjectIdentifier(GCCParser.T124_02_98_OID))
        stream.write(per.writeLength(len(pdu.payload) + 14))
        stream.write(per.writeChoice(pdu.header))

        self.writers[pdu.header](stream, pdu)
        return stream.getvalue()

    def writeConferenceCreateRequest(self, stream, pdu):
        """
        Read a GCCConferenceCreateRequestPDU and put its raw data into stream
        :param stream: byte stream to put the ConferenceCreateRequest data in
        :type stream: StringIO
        :type pdu: GCCConferenceCreateRequestPDU
        """
        stream.write(per.writeSelection(8))
        stream.write(per.writeNumericString(pdu.conferenceName, 1))
        stream.write(per.writeEnumeration(0))
        stream.write(per.writeNumberOfSet(1))
        stream.write(per.writeChoice(0xc0))
        stream.write(per.writeOctetStream(GCCParser.H221_CLIENT_KEY, 4))
        stream.write(per.writeOctetStream(pdu.payload))

    def writeConferenceCreateResponse(self, stream, pdu):
        """
        Read a GCCConferenceCreateResponsePDU and put its raw data into stream
        :param stream: byte stream to put the ConferenceCreateResponse data in
        :type stream: StringIO
        :type pdu: GCCConferenceCreateResponsePDU
        """

        stream.write(Uint16BE.pack(GCCParser.NODE_ID - 1001))
        stream.write(per.writeInteger(1))
        stream.write(per.writeEnumeration(0))
        stream.write(per.writeNumberOfSet(1))
        stream.write(per.writeChoice(0xc0))
        stream.write(per.writeOctetStream(GCCParser.H221_SERVER_KEY, 4))
        stream.write(per.writeOctetStream(pdu.payload))
