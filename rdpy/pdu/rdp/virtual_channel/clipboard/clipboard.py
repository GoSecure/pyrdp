from rdpy.pdu.base_pdu import PDU


class ClipboardPDU(PDU):
    """
    Not a PDU, just a base class for every other clipboard PDUs.
    https://msdn.microsoft.com/en-us/library/cc241097.aspx
    """

    def __init__(self, msgType, msgFlags, payload=None):
        PDU.__init__(self, payload)
        self.msgType = msgType
        self.msgFlags = msgFlags
