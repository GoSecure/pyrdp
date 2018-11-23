from rdpy.pdu.base_pdu import PDU


class SegmentationPDU(PDU):
    def __init__(self, payload):
        """
        :type payload: bytes
        """
        PDU.__init__(self, payload)

    def getSegmentationType(self):
        raise NotImplementedError("getType must be overridden")

