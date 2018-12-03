from rdpy.layer.buffered import BufferedLayer
from rdpy.parser.segmentation import SegmentationParser
from rdpy.parser.tpkt import TPKTParser
from rdpy.pdu.tpkt import TPKTPDU


class TPKTLayer(BufferedLayer):
    def __init__(self, parser = TPKTParser()):
        """
        :type parser: SegmentationParser
        """
        BufferedLayer.__init__(self, parser)

    def send(self, data):
        pdu = TPKTPDU(data)
        self.sendPDU(pdu)