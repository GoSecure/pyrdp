from pyrdp.pdu.base_pdu import PDU


class RDPSecurityPDU(PDU):
    def __init__(self, header, payload):
        PDU.__init__(self, payload)
        self.header = header


class RDPSecurityExchangePDU(PDU):
    def __init__(self, header, clientRandom):
        super().__init__()
        self.header = header
        self.clientRandom = clientRandom
