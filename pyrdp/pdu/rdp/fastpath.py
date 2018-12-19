#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import List, Optional

from pyrdp.enum import SegmentationPDUType
from pyrdp.pdu.pdu import PDU
from pyrdp.pdu.rdp.bitmap import BitmapUpdateData
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


class FastPathEvent(PDU):
    """
    Base class for RDP fast path event (not PDU, a PDU contains multiple events).
    Used for scan code events, mouse events or bitmap events.
    """

    def __init__(self, payload=b""):
        super().__init__(payload)


class FastPathEventRaw(FastPathEvent):
    def __init__(self, data):
        super().__init__()
        self.data = data


class FastPathInputEvent(FastPathEvent):
    def __init__(self):
        super().__init__()


class FastPathOutputUpdateEvent(FastPathEvent):
    """
    https://msdn.microsoft.com/en-us/library/cc240622.aspx
    """
    def __init__(self, header: int, compressionFlags: Optional[int], payload=b""):
        super().__init__(payload)
        self.header = header
        self.compressionFlags = compressionFlags


class FastPathScanCodeEvent(FastPathInputEvent):

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


class FastPathMouseEvent(FastPathInputEvent):
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


class FastPathBitmapEvent(FastPathOutputUpdateEvent):
    def __init__(self, header: int, compressionFlags: int, bitmapUpdateData: List[BitmapUpdateData],
                 payload: bytes):
        super().__init__(header, compressionFlags, payload)
        self.compressionFlags = compressionFlags
        self.bitmapUpdateData = bitmapUpdateData


class FastPathOrdersEvent(FastPathOutputUpdateEvent):
    """
    https://msdn.microsoft.com/en-us/library/cc241573.aspx
    """
    def __init__(self, header, compressionFlags, orderCount, orderData):
        super().__init__(header, compressionFlags)
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
