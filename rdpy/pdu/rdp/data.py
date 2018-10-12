class RDPShareControlHeader:
    def __init__(self, type, version, source):
        self.type = type
        self.version = version
        self.source = source

class RDPDemandActivePDU:
    def __init__(self, header, shareID, lengthCombinedCapabilities, sourceDescriptor, numberCapabilities, capabilitySets, sessionID):
        self.header = header
        self.shareID = shareID
        self.lengthCombinedCapabilities = lengthCombinedCapabilities
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets
        self.sessionID = sessionID