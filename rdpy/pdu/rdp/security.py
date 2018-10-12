class RDPBasicSecurityPDU:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

class RDPSignedSecurityPDU:
    def __init__(self, header, signature, payload):
        self.header = header
        self.signature = signature
        self.payload = payload

class RDPFIPSSecurityPDU:
    def __init__(self, header, version, padLength, signature, payload):
        self.header = header
        self.version = version
        self.padLength = padLength
        self.signature = signature
        self.payload = payload

class RDPSecurityExchangePDU:
    def __init__(self, header, clientRandom):
        self.header = header
        self.clientRandom = clientRandom

