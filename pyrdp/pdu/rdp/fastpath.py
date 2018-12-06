from typing import List

from pyrdp.enum import SegmentationPDUType
from pyrdp.pdu.base_pdu import PDU
from pyrdp.pdu.rdp.common import BitmapUpdateData
from pyrdp.pdu.segmentation import SegmentationPDU


class RDPFastPathPDU(SegmentationPDU):
    def __init__(self, header, events):
        PDU.__init__(self)
        self.header = header
        self.events = events

    def getSegmentationType(self):
        return SegmentationPDUType.FAST_PATH

    def __repr__(self):
        return str([str(e.__class__) for e in self.events])


class FastPathEventRaw(PDU):
    def __init__(self, data):
        super().__init__()
        self.data = data


class RDPFastPathEvent(PDU):
    """
    Base class for RDP fast path event (not PDU, a PDU contains multiple events)
    such as a scancode event, a mouse event or a bitmap event.
    """

    def __init__(self):
        super().__init__()


class FastPathEventScanCode(RDPFastPathEvent):

    def __init__(self, rawHeaderByte, scancode, isReleased):
        """
        :type rawHeaderByte: bytes
        :type scancode: bytes
        :type isReleased: bool
        """
        RDPFastPathEvent.__init__(self)
        self.rawHeaderByte = rawHeaderByte
        self.scancode = scancode
        self.isReleased = isReleased


class FastPathEventMouse(RDPFastPathEvent):
    """
    Mouse event (clicks, move, scroll, etc.)
    """

    def __init__(self, rawHeaderByte, pointerFlags, mouseX, mouseY):
        """
        :type rawHeaderByte: int
        :type pointerFlags: int
        :type mouseX: int
        :type mouseY: int
        """
        RDPFastPathEvent.__init__(self)
        self.rawHeaderByte = rawHeaderByte
        self.mouseY = mouseY
        self.mouseX = mouseX
        self.pointerFlags = pointerFlags


class FastPathOutputEvent(PDU):
    def __init__(self):
        super().__init__()


class FastPathBitmapEvent(FastPathOutputEvent):
    def __init__(self, header: int, compressionFlags: int, bitmapUpdateData: List[BitmapUpdateData],
                 rawBitmapUpdateData: bytes):
        super().__init__()
        self.header = header
        self.compressionFlags = compressionFlags
        self.rawBitmapUpdateData = rawBitmapUpdateData
        self.bitmapUpdateData = bitmapUpdateData


class FastPathOrdersEvent(FastPathOutputEvent):
    """
    https://msdn.microsoft.com/en-us/library/cc241573.aspx
    """
    def __init__(self, header, compressionFlags, orderCount, orderData):
        super().__init__()
        self.header = header
        self.compressionFlags = compressionFlags
        self.orderCount = orderCount
        self.orderData = orderData
        self.secondaryDrawingOrders = None


class SecondaryDrawingOrder(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241611.aspx
    """
    def __init__(self, controlFlags, orderLength, extraFlags, orderType, payload):
        super().__init__(payload)
        self.controlFlags = controlFlags
        self.orderLength = orderLength
        self.extraFlags = extraFlags
        self.orderType = orderType
        self.payload = payload
