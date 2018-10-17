from rdpy.enum.gcc import GCCPDUType
from rdpy.pdu.base_pdu import PDU

class GCCPDU(PDU):
    """
    Base PDU class for GCC (T.124) PDUs. Every GCC PDU has a header and a payload.
    """

    def __init__(self, header, payload):
        """
        :param header:
        :param payload: GCC's payload (so probably some RDP connection data).
        :type payload: str
        """

        PDU.__init__(self, payload)
        self.header = header


class GCCConferenceCreateRequestPDU(GCCPDU):
    def __init__(self, conferenceName, payload):
        GCCPDU.__init__(self, GCCPDUType.CREATE_CONFERENCE_REQUEST, payload)
        self.conferenceName = conferenceName


class GCCConferenceCreateResponsePDU(GCCPDU):
    def __init__(self, nodeID, tag, result, payload):
        GCCPDU.__init__(self, GCCPDUType.CREATE_CONFERENCE_RESPONSE, payload)
        self.nodeID = nodeID
        self.tag = tag
        self.result = result
