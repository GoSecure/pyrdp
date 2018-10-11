class TPKTPDU:
    """
    @summary: TPKT PDU definition
    """

    def __init__(self, version, payload):
        self.version = version
        self.padding = 0
        self.length = len(payload) + 4
        self.payload = payload