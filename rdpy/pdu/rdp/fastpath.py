class RDPFastPathPDU:
    def __init__(self, header, events):
        self.header = header
        self.events = events

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
