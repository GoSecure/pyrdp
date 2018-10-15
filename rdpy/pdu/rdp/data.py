class RDPShareControlHeader:
    def __init__(self, type, version, source):
        self.type = type
        self.version = version
        self.source = source

class RDPShareDataHeader(RDPShareControlHeader):
    def __init__(self, type, version, source, shareID, streamID, uncompressedLength, subtype, compressedType, compressedLength):
        RDPShareControlHeader.__init__(self, type, version, source)
        self.shareID = shareID
        self.streamID = streamID
        self.uncompressedLength = uncompressedLength
        self.subtype = subtype
        self.compressedType = compressedType
        self.compressedLength = compressedLength


class RDPDemandActivePDU:
    def __init__(self, header, shareID, sourceDescriptor, numberCapabilities, capabilitySets, sessionID):
        self.header = header
        self.shareID = shareID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets
        self.sessionID = sessionID

class RDPConfirmActivePDU:
    def __init__(self, header, shareID, originatorID, sourceDescriptor, numberCapabilities, capabilitySets):
        self.header = header
        self.shareID = shareID
        self.originatorID = originatorID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets

class RDPSetErrorInfoPDU:
    def __init__(self, header, errorInfo):
        self.header = header
        self.errorInfo = errorInfo

class RDPSynchronizePDU:
    def __init__(self, header, messageType, targetUser):
        self.header = header
        self.messageType = messageType
        self.targetUser = targetUser
