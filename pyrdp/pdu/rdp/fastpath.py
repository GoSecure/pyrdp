#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import List, Optional, Union

from pyrdp.enum import SegmentationPDUType
from pyrdp.pdu.pdu import PDU
from pyrdp.pdu.rdp.bitmap import BitmapUpdateData
from pyrdp.pdu.segmentation import SegmentationPDU


class FastPathEvent(PDU):
    """
    Base class for RDP fast path event (not PDU, a PDU contains multiple events).
    Used for scan code events, mouse events or bitmap events.
    """

    def __init__(self, payload: bytes = b""):
        super().__init__(payload)


class FastPathPDU(SegmentationPDU):
    def __init__(self, header: int, events: [FastPathEvent]):
        super().__init__(b"")
        self.header = header
        self.events = events

    def getSegmentationType(self) -> SegmentationPDUType:
        return SegmentationPDUType.FAST_PATH

    def __repr__(self) -> str:
        return str([str(e.__class__) for e in self.events])

class FastPathEventRaw(FastPathEvent):
    def __init__(self, data: bytes):
        super().__init__()
        self.data = data


class FastPathInputEvent(FastPathEvent):
    def __init__(self):
        super().__init__()


class FastPathOutputEvent(FastPathEvent):
    """
    https://msdn.microsoft.com/en-us/library/cc240622.aspx
    """
    def __init__(self, header: int, compressionFlags: Optional[int], payload: bytes = b""):
        super().__init__(payload)
        self.header = header
        self.compressionFlags = compressionFlags


class FastPathScanCodeEvent(FastPathInputEvent):

    def __init__(self, rawHeaderByte: int, scanCode: int, isReleased: bool):
        super().__init__()
        self.rawHeaderByte = rawHeaderByte
        self.scanCode = scanCode
        self.isReleased = isReleased


class FastPathMouseEvent(FastPathInputEvent):
    """
    Mouse event (clicks, move, scroll, etc.)
    """

    def __init__(self, rawHeaderByte: int, pointerFlags: int, mouseX: int, mouseY: int):
        super().__init__()
        self.rawHeaderByte = rawHeaderByte
        self.mouseY = mouseY
        self.mouseX = mouseX
        self.pointerFlags = pointerFlags


class FastPathUnicodeEvent(FastPathInputEvent):
    """
    Unicode event (text presses and releases)
    """

    def __init__(self, text: Union[str, bytes], released: bool):
        super().__init__()
        self.text = text
        self.released = released


class FastPathBitmapEvent(FastPathOutputEvent):
    def __init__(self, header: int, compressionFlags: Optional[int], bitmapUpdateData: List[BitmapUpdateData], payload: bytes):
        super().__init__(header, compressionFlags, payload)
        self.bitmapUpdateData = bitmapUpdateData


class FastPathOrdersEvent(FastPathOutputEvent):
    """
    Encapsulate drawing orders.
    
    This is a specialization of TS_FP_UDPATE_ORDERS.

    https://msdn.microsoft.com/en-us/library/cc241573.aspx
    """
    def __init__(self, header: int, compressionFlags: Optional[int], payload: bytes):
        # Keep the payload to make writing easier, since in most cases
        # there is no need to actually modify the drawing orders.

        # NOTE: This could be further optimized by not even parsing
        # the orders in MITM mode.
        super().__init__(header, compressionFlags, payload=payload)
        self.compressionFlags = compressionFlags
        # self.secondaryDrawingOrders = None # TODO


# class SecondaryDrawingOrder:
#     """
#     https://msdn.microsoft.com/en-us/library/cc241611.aspx
#     """
#     def __init__(self, controlFlags: int, orderLength: int, extraFlags: int, orderType: int):
#         super().__init__()
#         self.controlFlags = controlFlags
#         self.orderLength = orderLength
#         self.extraFlags = extraFlags
#         self.orderType = orderType
