class RDPLicensingPDUType:
    LICENSE_REQUEST = 0x01
    PLATFORM_CHALLENGE = 0x02
    NEW_LICENSE = 0x03
    UPGRADE_LICENSE = 0x04
    LICENSE_INFO = 0x12
    NEW_LICENSE_REQUEST = 0x13
    PLATFORM_CHALLENGE_RESPONSE = 0x15

class RDPLicensingPDU:
    def __init__(self, msgType, flags):
        self.msgType = msgType
        self.flags = flags

class RDPServerLicenseRequest:
    def __init__(self, serverRandom, productInfo, keyExchangeList, serverCertificate, scopeList):
        self.serverRandom = serverRandom
        self.productInfo = productInfo
        self.keyExchangeList = keyExchangeList
        self.serverCertificate = serverCertificate
        self.scopeList = scopeList