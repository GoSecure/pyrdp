#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict

from pyrdp.enum import CapabilityType, SlowPathUpdateType
from pyrdp.pdu.pdu import PDU
from pyrdp.pdu.rdp.capability import Capability


class ShareControlHeader(PDU):
    def __init__(self, pduType, version, source):
        super().__init__()
        self.pduType = pduType
        self.version = version
        self.source = source


class ShareDataHeader(ShareControlHeader):
    def __init__(self, pduType, version, source, shareID, streamID, uncompressedLength, subtype, compressedType, compressedLength):
        ShareControlHeader.__init__(self, pduType, version, source)
        self.shareID = shareID
        self.streamID = streamID
        self.uncompressedLength = uncompressedLength
        self.subtype = subtype
        self.compressedType = compressedType
        self.compressedLength = compressedLength


class SlowPathPDU(PDU):
    """
    Base class for slow-path PDUs
    """

    def __init__(self, header: ShareControlHeader, payload: bytes = b""):
        super().__init__(payload)
        self.header = header


class SlowPathUnparsedPDU(SlowPathPDU):
    """
    Class for slow-path PDUs with unimplemented parsing
    """

    def __init__(self, header: ShareControlHeader, payload: bytes):
        super().__init__(header, payload)


class DemandActivePDU(SlowPathPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc240484.aspx
    """

    def __init__(self, header: ShareControlHeader, shareID: int, sourceDescriptor: bytes, numberCapabilities: int,
                 capabilitySets: bytes, sessionID: int, parsedCapabilitySets: Dict[CapabilityType, Capability] = None):

        super().__init__(header)
        self.shareID = shareID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.capabilitySets = capabilitySets
        self.sessionID = sessionID
        self.parsedCapabilitySets = parsedCapabilitySets


class ConfirmActivePDU(SlowPathPDU):
    def __init__(self, header, shareID, originatorID, sourceDescriptor, numberCapabilities, parsedCapabilitySets,
                 capabilitySetsRaw):

        super().__init__(header)
        self.shareID = shareID
        self.originatorID = originatorID
        self.sourceDescriptor = sourceDescriptor
        self.numberCapabilities = numberCapabilities
        self.parsedCapabilitySets = parsedCapabilitySets
        self.capabilitySets = capabilitySetsRaw


class SetErrorInfoPDU(SlowPathPDU):
    def __init__(self, header, errorInfo):
        super().__init__(header)
        self.errorInfo = errorInfo


class SynchronizePDU(SlowPathPDU):
    def __init__(self, header, messageType, targetUser):

        super().__init__(header)
        self.messageType = messageType
        self.targetUser = targetUser


class ControlPDU(SlowPathPDU):
    def __init__(self, header, action, grantID, controlID):
        super().__init__(header)
        self.action = action
        self.grantID = grantID
        self.controlID = controlID


class InputPDU(SlowPathPDU):
    def __init__(self, header, events):
        super().__init__(header)
        self.header = header
        self.events = events


class PlaySoundPDU(SlowPathPDU):
    def __init__(self, header, duration, frequency):
        super().__init__(header)
        self.duration = duration
        self.frequency = frequency


class PointerPDU(SlowPathPDU):
    def __init__(self, header, event):

        super().__init__(header)
        self.event = event


class SuppressOutputPDU(SlowPathPDU):
    def __init__(self, header, allowDisplayUpdates, left, top, right, bottom):

        super().__init__(header)
        self.allowDisplayUpdates = bool(allowDisplayUpdates)
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom


class UpdatePDU(SlowPathPDU):
    def __init__(self, header: ShareDataHeader, updateType: SlowPathUpdateType, updateData: bytes):
        super().__init__(header)
        self.updateType = updateType
        self.updateData = updateData
