from rdpy.pdu.base_pdu import PDU


class RDPPlayerMessagePDU(PDU):
    """
    PDU to encapsulate different types (ex: input, output, creds) for (re)play purposes.
    Also contains a timestamp.
    """

    def __init__(self, type, timestamp, payload):
        """
        :type type: rdpy.enum.rdp.RDPPlayerMessageType
        :type payload: str
        """

        self.type = type  # Uint8
        self.timestamp = timestamp  # Uint64LE
        PDU.__init__(self, payload)
