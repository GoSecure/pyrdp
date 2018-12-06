from pyrdp.layer.buffered import BufferedLayer
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.parser.tpkt import TPKTParser
from pyrdp.pdu import TPKTPDU


class TPKTLayer(BufferedLayer):
    def __init__(self, parser = TPKTParser()):
        """
        :type parser: SegmentationParser
        """
        BufferedLayer.__init__(self, parser)

    def send(self, data):
        pdu = TPKTPDU(data)
        self.sendPDU(pdu)