from rdpy.layer.buffered import BufferedLayer
from rdpy.parser.segmentation import SegmentationParser


class FastPathLayer(BufferedLayer):
    def __init__(self, parser):
        """
        :type parser: SegmentationParser
        """
        BufferedLayer.__init__(self, parser)

    def send(self, data):
        raise NotImplementedError("FastPathLayer does not implement the send method. Use sendPDU instead.")