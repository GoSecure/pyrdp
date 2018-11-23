from rdpy.pdu.base_pdu import PDU


class RDPPlayerMessagePDU(PDU):
    """
    PDU to encapsulate different types (ex: input, output, creds) for (re)play purposes.
    Also contains a timestamp.
    """

    def __init__(self, header, timestamp, payload):
        """
        :type header: rdpy.enum.rdp.RDPPlayerMessageType
        :type payload: bytes
        """

        self.header = header  # Uint8
        self.timestamp = timestamp  # Uint64LE
        PDU.__init__(self, payload)
