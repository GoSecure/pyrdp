from rdpy.enum.segmentation import SegmentationPDUType
from rdpy.pdu.base_pdu import PDU
from rdpy.pdu.segmentation import SegmentationPDU


class TPKTPDU(SegmentationPDU):

    def __init__(self, payload):
        """
        :type payload: str
        """
        PDU.__init__(self, payload)
        self.header = 3

    def getSegmentationType(self):
        return SegmentationPDUType.TPKT