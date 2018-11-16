from rdpy.enum.segmentation import SegmentationPDUType
from rdpy.pdu.base_pdu import PDU
from rdpy.pdu.segmentation import SegmentationPDU


class RDPFastPathPDU(SegmentationPDU):
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
        self.data = data


class RDPFastPathEvent:
    """
    Base class for RDP fast path event (not PDU, a PDU contains multiple events)
    such as a scancode event, a mouse event or a bitmap event.
    """

    def __init__(self):
        pass


class FastPathEventScanCode(RDPFastPathEvent):

    def __init__(self, rawHeaderByte, scancode, isReleased):
        """
        :type rawHeaderByte: str
        :type scancode: str
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


class FastPathOutputEvent:
    pass


class FastPathBitmapEvent(FastPathOutputEvent):
    def __init__(self, header, compressionFlags, bitmapUpdateData, rawBitmapUpdateData):
        """
        :type header: int
        :type compressionFlags: int
        :type bitmapUpdateData: list[BitmapUpdateData]
        :type rawBitmapUpdateData: str
        """
        self.header = header
        self.compressionFlags = compressionFlags
        self.rawBitmapUpdateData = rawBitmapUpdateData
        self.bitmapUpdateData = bitmapUpdateData


class BitmapUpdateData:
    """
    https://msdn.microsoft.com/en-us/library/cc240612.aspx
    """

    def __init__(self, destLeft, destTop, destRight, destBottom, width, heigth, bitsPerPixel, flags, bitmapStream):
        self.destLeft = destLeft
        self.destTop = destTop
        self.destRight = destRight
        self.destBottom = destBottom
        self.width = width
        self.heigth = heigth
        self.bitsPerPixel = bitsPerPixel
        self.flags = flags
        self.bitmapStream = bitmapStream


class FastPathOrdersEvent(FastPathOutputEvent):
    """
    https://msdn.microsoft.com/en-us/library/cc241573.aspx
    """
    def __init__(self, header, compressionFlags, orderCount, orderData):
        self.header = header
        self.compressionFlags = compressionFlags
        self.orderCount = orderCount
        self.orderData = orderData
        self.secondaryDrawingOrders = None


class SecondaryDrawingOrder:
    """
    https://msdn.microsoft.com/en-us/library/cc241611.aspx
    """
    def __init__(self, controlFlags, orderLength, extraFlags, orderType, payload):
        self.controlFlags = controlFlags
        self.orderLength = orderLength
        self.extraFlags = extraFlags
        self.orderType = orderType
        self.payload = payload
