from pyrdp.pdu import PDU


class TCPPDU(PDU):
    """
    A TCP PDU (contains only the TCP payload).
    """
    def __init__(self, payload: bytes):
        super().__init__(payload)