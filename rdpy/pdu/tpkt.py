from rdpy.pdu.base_pdu import PDU


class TPKTPDU(PDU):

    def __init__(self, version, payload):
        """
        :param version: usually 3
        :type payload: str
        """

        PDU.__init__(self, payload)
        self.version = version
        self.padding = 0  # Unused byte
        self.length = len(payload) + 4
