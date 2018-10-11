from rdpy.protocol.gcc.pdu import GCCPDUType


class GCCPDU(object):
    def __init__(self, header, payload):
        self.header = header
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