from pyrdp.enum import SegmentationPDUType
from pyrdp.pdu.pdu import PDU
from pyrdp.pdu.segmentation import SegmentationPDU


class TPKTPDU(SegmentationPDU):

    def __init__(self, payload):
        """
        :type payload: bytes
        """
        PDU.__init__(self, payload)
        self.header = 3

    def getSegmentationType(self):
        return SegmentationPDUType.TPKT