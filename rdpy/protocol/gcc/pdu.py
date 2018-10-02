from StringIO import StringIO

from rdpy.core import per
from rdpy.core.packing import Uint16BE

class GCCPDUType:
    CREATE_CONFERENCE_REQUEST = 0
    CREATE_CONFERENCE_RESPONSE = 0x14

class GCCPDU:
    def __init__(self, header, payload):
        self.header = GCCPDUType.CREATE_CONFERENCE_REQUEST
        self.payload = payload

class GCCConferenceCreateRequestPDU(GCCPDU):
    def __init__(self, conferenceName, payload):
        super(GCCConferenceCreateRequestPDU, self).__init__(GCCPDUType.CREATE_CONFERENCE_REQUEST, payload)
        self.conferenceName = conferenceName

class GCCConferenceCreateResponsePDU(GCCPDU):
    def __init__(self, nodeID, tag, result, payload):
        super(GCCConferenceCreateResponsePDU, self).__init__(GCCPDUType.CREATE_CONFERENCE_RESPONSE, payload)
        self.nodeID = nodeID
        self.tag = tag
        self.result = result

class GCCParser:
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
        stream = StringIO(data)
        
        tag = per.readChoice(stream)

        if tag != 0:
            raise Exception("Expected object tag (0), got %d instead" % tag)

        oid = per.readObjectIdentifier(stream)

        if oid != GCCParser.T124_02_98_OID:
            raise Exception("Invalid object identifier: %r" % oid)

        length = per.readLength(stream)
        header = per.readChoice(stream)

        if header not in self.parsers:
            raise Exception("Trying to parse unknown GCC PDU type %d" % header)
        
        pdu = self.parsers[header](stream)

        if len(pdu.payload) != length - 14:
            raise Exception("Invalid size received in GCC PDU")
        
        return pdu
    
    def parseConferenceCreateRequest(self, stream, length):
        property = per.readSelection(stream)
        if property != 8:
            raise Exception("Expected property to be 8 (conference name), got %d" % choice)
        
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

    def parseConferenceCreateResponse(self, stream, length):
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
    
        stream.write(per.writeChoice(0))
        stream.write(per.writeObjectIdentifier(GCCParser.T124_02_98_OID))
        stream.write(per.writeLength(len(pdu.payload) + 14))
        stream.write(per.writeChoice(pdu.header))

        stream = StringIO()
        self.writers[pdu.type](stream, pdu)
        return stream.getvalue()
    
    def writeConferenceCreateRequest(self, stream, pdu):
        stream.write(per.writeSelection(8))
        stream.write(per.writeNumericString(pdu.conferenceName, 1))
        stream.write(per.writeEnumeration(0))
        stream.write(per.writeNumberOfSet(1))
        stream.write(per.writeChoice(0xc0))
        stream.write(per.writeOctetStream(GCCParser.H221_CLIENT_KEY, 4))
        stream.write(per.writeOctetStream(pdu.payload))
    
    def writeConferenceCreateResponse(self, stream, pdu):
        stream.write(Uint16BE.pack(GCCParser.NODE_ID - 1001))
        stream.write(per.writeInteger(1))
        stream.write(per.writeEnumeration(0))
        stream.write(per.writeNumberOfSet(1))
        stream.write(per.writeChoice(0xc0))
        stream.write(per.writeOctetStream(GCCParser.H221_SERVER_KEY, 4))
        stream.write(per.writeOctetStream(pdu.payload))