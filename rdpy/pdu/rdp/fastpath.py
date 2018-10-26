class RDPFastPathPDU:
    def __init__(self, header, events):
        self.header = header
        self.events = events

class FastPathEventRaw:
    def __init__(self, data):
        self.data = data