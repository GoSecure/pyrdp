from pyrdp.pdu.pdu import PDU


class SecurityPDU(PDU):
    def __init__(self, header, payload):
        PDU.__init__(self, payload)
        self.header = header


class SecurityExchangePDU(PDU):
    def __init__(self, header, clientRandom):
        super().__init__()
        self.header = header
        self.clientRandom = clientRandom
