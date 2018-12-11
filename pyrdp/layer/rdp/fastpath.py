from pyrdp.layer import LayerObserver
from pyrdp.layer.buffered import BufferedLayer
from pyrdp.layer.rdp.slowpath import RDPDataLayerObserver
from pyrdp.parser import SegmentationParser


class RDPFastPathDataLayerObserver(RDPDataLayerObserver, LayerObserver):
    """
    Base observer class for fast-path PDUs.
    """

    def onPDUReceived(self, pdu):
        self.dispatchPDU(pdu)

    def getPDUType(self, pdu):
        # The PDU type is stored in the last 3 bits
        return pdu.header & 0b11100000


class FastPathLayer(BufferedLayer):
    def __init__(self, parser):
        """
        :type parser: SegmentationParser
        """
        BufferedLayer.__init__(self, parser)

    def send(self, data):
        raise NotImplementedError("FastPathLayer does not implement the send method. Use sendPDU instead.")