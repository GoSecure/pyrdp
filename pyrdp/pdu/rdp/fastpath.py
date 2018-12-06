from typing import List

from pyrdp.enum import SegmentationPDUType
from pyrdp.pdu.pdu import PDU
from pyrdp.pdu.rdp.common import BitmapUpdateData
from pyrdp.pdu.segmentation import SegmentationPDU


class FastPathPDU(SegmentationPDU):
    def __init__(self, header, events):
        PDU.__init__(self)
        self.header = header
        self.events = events

    def getSegmentationType(self):
        return SegmentationPDUType.FAST_PATH

    def __repr__(self):
        return str([str(e.__class__) for e in self.events])


class FastPathEventRaw:
    def __init__(self, data):
        super().__init__()
        self.data = data


class FastPathEvent:
    """
    Base class for RDP fast path event (not PDU, a PDU contains multiple events).
    Used for scan code events, mouse events or bitmap events.
    """

    def __init__(self):
        super().__init__()


class FastPathScanCodeEvent(FastPathEvent):

    def __init__(self, rawHeaderByte, scancode, isReleased):
        """
        :type rawHeaderByte: bytes
        :type scancode: bytes
        :type isReleased: bool
        """
        FastPathEvent.__init__(self)
        self.rawHeaderByte = rawHeaderByte
        self.scancode = scancode
        self.isReleased = isReleased


class FastPathMouseEvent(FastPathEvent):
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
        FastPathEvent.__init__(self)
        self.rawHeaderByte = rawHeaderByte
        self.mouseY = mouseY
        self.mouseX = mouseX
        self.pointerFlags = pointerFlags


class FastPathOutputEvent:
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


class SecondaryDrawingOrder:
    """
    https://msdn.microsoft.com/en-us/library/cc241611.aspx
    """
    def __init__(self, controlFlags, orderLength, extraFlags, orderType):
        super().__init__()
        self.controlFlags = controlFlags
        self.orderLength = orderLength
        self.extraFlags = extraFlags
        self.orderType = orderType
