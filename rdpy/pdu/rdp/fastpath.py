class RDPFastPathPDU:
    def __init__(self, header, events):
        self.header = header
        self.events = events

    def __repr__(self):
        return str([str(e.__class__) for e in self.events])

class FastPathEventRaw:
    def __init__(self, data):
        self.data = data


class RDPFastPathEvent:
    """
    Base class for RDP fast path event (not PDU, a PDU contains multiple events)
    """

    def __init__(self, timestamp):
        # Even though an event does not contain a timestamp, it is needed for replay purposes.
        self.timestamp = timestamp


class FastPathEventScanCode(RDPFastPathEvent):

    def __init__(self, rawHeaderByte, scancode, isReleased, timestamp=None):
        RDPFastPathEvent.__init__(self, timestamp)
        self.rawHeaderByte = rawHeaderByte
        self.scancode = scancode
        self.isReleased = isReleased




class FastPathOutputEvent:
    pass

class FastPathBitmapEvent(FastPathOutputEvent):
    def __init__(self, header, compressionFlags, bitmapUpdateData):
        self.header = header
        self.compressionFlags = compressionFlags
        self.bitmapUpdateData = bitmapUpdateData

class FastPathOrdersEvent(FastPathOutputEvent):
    def __init__(self, header, compressionFlags, orderCount, orderData):
        self.header = header
        self.compressionFlags = compressionFlags
        self.orderCount = orderCount
        self.orderData = orderData