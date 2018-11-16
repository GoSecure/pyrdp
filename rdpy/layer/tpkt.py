from rdpy.core.newlayer import Layer
from rdpy.enum.segmentation import SegmentationPDUType
from rdpy.layer.segmentation import SegmentationLayer
from rdpy.parser.tpkt import TPKTParser
from rdpy.pdu.tpkt import TPKTPDU


class TPKTLayer(SegmentationLayer):
    def __init__(self):
        SegmentationLayer.__init__(self)
        self.setParser(SegmentationPDUType.TPKT, TPKTParser())

    def pduReceived(self, pdu, forward):
        SegmentationLayer.pduReceived(self, pdu, pdu.getSegmentationType() == SegmentationPDUType.TPKT)

    def send(self, data):
        self.sendPDU(TPKTPDU(data))


class TPKTProxyLayer(Layer):
    def __init__(self, segmentation):
        """
        :type segmentation: SegmentationLayer
        """
        Layer.__init__(self)
        self.segmentation = segmentation
        self.parser = TPKTParser()

    def recv(self, data):
        raise NotImplementedError("recv is not supported for TPKTProxyLayer")

    def send(self, data):
        self.segmentation.sendPDU(TPKTPDU(data))