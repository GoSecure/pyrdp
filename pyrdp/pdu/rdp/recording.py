from pyrdp.enum.rdp import PlayerMessageType
from pyrdp.pdu.base_pdu import PDU


class RDPPlayerMessagePDU(PDU):
    """
    PDU to encapsulate different types (ex: input, output, creds) for (re)play purposes.
    Also contains a timestamp.
    """

    def __init__(self, header: PlayerMessageType, timestamp: int, payload: bytes):
        self.header = header  # Uint8
        self.timestamp = timestamp  # Uint64LE
        PDU.__init__(self, payload)
