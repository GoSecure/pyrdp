from rdpy.pdu.base_pdu import PDU


class RDPSecurityBasePDU(PDU):
    """
    base class for RDP Security PDUs. They all have flags (2 used bytes + 2 unused bytes) and a payload.
    """

    def __init__(self, flags, payload):
        PDU.__init__(self, payload)
        self.header = flags


class RDPBasicSecurityPDU(RDPSecurityBasePDU):
    def __init__(self, flags, payload):
        RDPSecurityBasePDU.__init__(self, flags, payload)


class RDPSignedSecurityPDU(RDPSecurityBasePDU):
    def __init__(self, flags, signature, payload):
        RDPSecurityBasePDU.__init__(self, flags, payload)
        self.signature = signature


class RDPFIPSSecurityPDU(RDPSecurityBasePDU):
    def __init__(self, flags, version, padLength, signature, payload):
        RDPSecurityBasePDU.__init__(self, flags, payload)
        self.version = version
        self.padLength = padLength
        self.signature = signature


class RDPSecurityExchangePDU:
    def __init__(self, header, clientRandom):
        self.header = header
        self.clientRandom = clientRandom

