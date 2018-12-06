from pyrdp.enum import SlowPathUpdateType
from pyrdp.pdu.pdu import PDU


class RDPShareControlHeader(PDU):
    def __init__(self, type, version, source):
        super().__init__()
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
    def __init__(self, header, shareID, sourceDescriptor, numberCapabilities, capabilitySets, sessionID, parsedCapabilitySets=None):
        PDU.__init__(self)
        self.header = header
        self.shareID = shareID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets
        self.sessionID = sessionID
        self.parsedCapabilitySets = parsedCapabilitySets


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


class RDPSetErrorInfoPDU(PDU):
    def __init__(self, header, errorInfo):
        PDU.__init__(self)
        self.header = header
        self.errorInfo = errorInfo


class RDPSynchronizePDU(PDU):
    def __init__(self, header, messageType, targetUser):
        PDU.__init__(self)
        self.header = header
        self.messageType = messageType
        self.targetUser = targetUser


class RDPControlPDU(PDU):
    def __init__(self, header, action, grantID, controlID):
        PDU.__init__(self)
        self.header = header
        self.action = action
        self.grantID = grantID
        self.controlID = controlID


class RDPInputPDU(PDU):
    def __init__(self, header, events):
        PDU.__init__(self)
        self.header = header
        self.events = events


class RDPPlaySoundPDU(PDU):
    def __init__(self, header, duration, frequency):
        PDU.__init__(self)
        self.header = header
        self.duration = duration
        self.frequency = frequency


class RDPPointerPDU(PDU):
    def __init__(self, header, event):
        PDU.__init__(self)
        self.header = header
        self.event = event


class RDPSuppressOutputPDU(PDU):
    def __init__(self, header, allowDisplayUpdates, left, top, right, bottom):
        PDU.__init__(self)
        self.header = header
        self.allowDisplayUpdates = bool(allowDisplayUpdates)
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom


class RDPUpdatePDU(PDU):
    def __init__(self, header: RDPShareDataHeader, updateType: SlowPathUpdateType, updateData: bytes):
        PDU.__init__(self)
        self.header = header
        self.updateType = updateType
        self.updateData = updateData
