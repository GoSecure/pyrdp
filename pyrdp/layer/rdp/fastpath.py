from pyrdp.core import ObservedBy
from pyrdp.layer.buffered import BufferedLayer
from pyrdp.layer.layer import LayerObserver
from pyrdp.layer.rdp.data import RDPDataObserver
from pyrdp.parser import SegmentationParser
from pyrdp.pdu.rdp.fastpath import FastPathPDU


class FastPathObserver(RDPDataObserver, LayerObserver):
    """
    Observer for fast-path PDUs.
    """

    def onPDUReceived(self, pdu: FastPathPDU):
        self.dispatchPDU(pdu)

    def getPDUType(self, pdu):
        # The PDU type is stored in the last 3 bits
        return pdu.header & 0b11100000


@ObservedBy(FastPathObserver)
class FastPathLayer(BufferedLayer):
    """
    Layer for fast-path PDUs.
    """

    def __init__(self, parser: SegmentationParser):
        BufferedLayer.__init__(self, parser)

    def send(self, data: bytes):
        raise NotImplementedError("FastPathLayer does not implement the send method. Use sendPDU instead.")