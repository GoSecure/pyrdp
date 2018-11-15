from rdpy.pdu.base_pdu import PDU


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


class RDPDemandActivePDU(PDU):
    def __init__(self, header, shareID, sourceDescriptor, numberCapabilities, capabilitySets, sessionID):
        PDU.__init__(self)
        self.header = header
        self.shareID = shareID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets
        self.sessionID = sessionID


class RDPConfirmActivePDU(PDU):
    def __init__(self, header, shareID, originatorID, sourceDescriptor, numberCapabilities, parsedCapabilitySets,
                 capabilitySetsRaw):
        PDU.__init__(self)
        self.header = header
        self.shareID = shareID
        self.originatorID = originatorID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.parsedCapabilitySets = parsedCapabilitySets
        self.capabilitySets = capabilitySetsRaw


class RDPSetErrorInfoPDU:
    def __init__(self, header, errorInfo):
        self.header = header
        self.errorInfo = errorInfo


class RDPSynchronizePDU:
    def __init__(self, header, messageType, targetUser):
        self.header = header
        self.messageType = messageType
        self.targetUser = targetUser


class RDPControlPDU:
    def __init__(self, header, action, grantID, controlID):
        self.header = header
        self.action = action
        self.grantID = grantID
        self.controlID = controlID


class RDPInputPDU:
    def __init__(self, header, events):
        self.header = header
        self.events = events


class RDPPlaySoundPDU:
    def __init__(self, header, duration, frequency):
        self.header = header
        self.duration = duration
        self.frequency = frequency


class RDPPointerPDU:
    def __init__(self, header, event):
        self.header = header
        self.event = event

class RDPSuppressOutputPDU:
    def __init__(self, header, allowDisplayUpdates, left, top, right, bottom):
        self.header = header
        self.allowDisplayUpdates = bool(allowDisplayUpdates)
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

