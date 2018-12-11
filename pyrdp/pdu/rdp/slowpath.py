from typing import Dict

from pyrdp.enum import CapabilityType, SlowPathUpdateType
from pyrdp.pdu.pdu import PDU
from pyrdp.pdu.rdp.capability import Capability


class RDPShareControlHeader(PDU):
    def __init__(self, pduType, version, source):
        super().__init__()
        self.pduType = pduType
        self.version = version
        self.source = source


class RDPShareDataHeader(RDPShareControlHeader):
    def __init__(self, pduType, version, source, shareID, streamID, uncompressedLength, subtype, compressedType, compressedLength):
        RDPShareControlHeader.__init__(self, pduType, version, source)
        self.shareID = shareID
        self.streamID = streamID
        self.uncompressedLength = uncompressedLength
        self.subtype = subtype
        self.compressedType = compressedType
        self.compressedLength = compressedLength


class RDPSlowPathPDU(PDU):
    """
    Base class for slow-path PDUs
    """

    def __init__(self, header: RDPShareControlHeader):
        super().__init__()
        self.header = header


class RDPDemandActivePDU(RDPSlowPathPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc240484.aspx
    """

    def __init__(self, header: RDPShareControlHeader, shareID: int, sourceDescriptor: bytes, numberCapabilities: int,
                 capabilitySets: bytes, sessionID: int, parsedCapabilitySets: Dict[CapabilityType, Capability] = None):

        super().__init__(header)
        self.shareID = shareID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets
        self.sessionID = sessionID
        self.parsedCapabilitySets = parsedCapabilitySets


class RDPConfirmActivePDU(RDPSlowPathPDU):
    def __init__(self, header, shareID, originatorID, sourceDescriptor, numberCapabilities, parsedCapabilitySets,
                 capabilitySetsRaw):

        super().__init__(header)
        self.shareID = shareID
        self.originatorID = originatorID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.parsedCapabilitySets = parsedCapabilitySets
        self.capabilitySets = capabilitySetsRaw


class RDPSetErrorInfoPDU(RDPSlowPathPDU):
    def __init__(self, header, errorInfo):
        super().__init__(header)
        self.errorInfo = errorInfo


class RDPSynchronizePDU(RDPSlowPathPDU):
    def __init__(self, header, messageType, targetUser):

        super().__init__(header)
        self.messageType = messageType
        self.targetUser = targetUser


class RDPControlPDU(RDPSlowPathPDU):
    def __init__(self, header, action, grantID, controlID):
        super().__init__(header)
        self.action = action
        self.grantID = grantID
        self.controlID = controlID


class RDPInputPDU(RDPSlowPathPDU):
    def __init__(self, header, events):
        super().__init__(header)
        self.header = header
        self.events = events


class RDPPlaySoundPDU(RDPSlowPathPDU):
    def __init__(self, header, duration, frequency):
        super().__init__(header)
        self.duration = duration
        self.frequency = frequency


class RDPPointerPDU(RDPSlowPathPDU):
    def __init__(self, header, event):

        super().__init__(header)
        self.event = event


class RDPSuppressOutputPDU(RDPSlowPathPDU):
    def __init__(self, header, allowDisplayUpdates, left, top, right, bottom):

        super().__init__(header)
        self.allowDisplayUpdates = bool(allowDisplayUpdates)
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom


class RDPUpdatePDU(RDPSlowPathPDU):
    def __init__(self, header: RDPShareDataHeader, updateType: SlowPathUpdateType, updateData: bytes):
        super().__init__(header)
        self.updateType = updateType
        self.updateData = updateData
