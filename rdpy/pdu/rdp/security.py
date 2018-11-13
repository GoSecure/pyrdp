from rdpy.pdu.base_pdu import PDU


class RDPSecurityPDU(PDU):
    def __init__(self, header, payload):
        PDU.__init__(self, payload)
        self.header = header


class RDPSecurityExchangePDU:
    def __init__(self, header, clientRandom):
        self.header = header
        self.clientRandom = clientRandom