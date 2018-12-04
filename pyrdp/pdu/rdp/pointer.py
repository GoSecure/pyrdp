from pyrdp.enum.rdp import PointerEventType
from pyrdp.pdu.base_pdu import PDU


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y


class PointerEvent(PDU):
    def __init__(self, messageType):
        super().__init__()
        self.messageType = messageType


class PointerSystemEvent(PointerEvent):
    def __init__(self, pointerType):
        PointerEvent.__init__(self, PointerEventType.TS_PTRMSGTYPE_SYSTEM)
        self.pointerType = pointerType


class PointerPositionEvent(PointerEvent):
    def __init__(self, point):
        PointerEvent.__init__(self, PointerEventType.TS_PTRMSGTYPE_POSITION)
        self.point = point


class PointerColorEvent(PointerEvent):
    def __init__(self, cacheIndex, hotSpot, width, height, andMask, xorMask):
        PointerEvent.__init__(self, PointerEventType.TS_PTRMSGTYPE_COLOR)
        self.cacheIndex = cacheIndex
        self.hotSpot = hotSpot
        self.width = width
        self.height = height
        self.andMask = andMask
        self.xorMask = xorMask


class PointerCacheEvent(PointerEvent):
    def __init__(self, cacheIndex):
        PointerEvent.__init__(self, PointerEventType.TS_PTRMSGTYPE_CACHED)
        self.cacheIndex = cacheIndex


class PointerNewEvent(PointerEvent):
    def __init__(self, xorBPP, color):
        PointerEvent.__init__(self, PointerEventType.TS_PTRMSGTYPE_POINTER)
        self.xorBPP = xorBPP
        self.color = color
