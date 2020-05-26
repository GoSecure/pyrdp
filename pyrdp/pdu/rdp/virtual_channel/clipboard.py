#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict

from pyrdp.enum import ClipboardMessageType, ClipboardMessageFlags, ClipboardFormatNumber
from pyrdp.pdu.pdu import PDU


class FormatName(PDU):
    def __init__(self, formatId: int, formatName: bytes):
        super().__init__()
        self.formatId = formatId
        self.formatName = formatName

    def __str__(self):
        return self.formatName.decode('utf-16le').strip('\x00')


class ShortFormatName(FormatName):
    """
    https://msdn.microsoft.com/en-us/library/cc241107.aspx
    """


class LongFormatName(FormatName):
    """
    https://msdn.microsoft.com/en-us/library/cc241109.aspx
    """


class ClipboardPDU(PDU):
    """
    Not a PDU, just a base class for every other clipboard PDUs.
    https://msdn.microsoft.com/en-us/library/cc241097.aspx
    """

    def __init__(self, msgType: ClipboardMessageType, msgFlags: ClipboardMessageFlags, payload: bytes = b""):
        PDU.__init__(self, payload)
        self.msgType = msgType
        self.msgFlags = msgFlags


class FormatDataRequestPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241122.aspx
    """

    def __init__(self, requestedFormatId: ClipboardFormatNumber):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_DATA_REQUEST, ClipboardMessageFlags.NONE)
        self.requestedFormatId = requestedFormatId


class FormatDataResponsePDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241123.aspx
    """

    def __init__(self, requestedFormatData: bytes, isSuccessful: bool = True, formatId = None):

        flags = ClipboardMessageFlags.CB_RESPONSE_OK if isSuccessful else ClipboardMessageFlags.CB_RESPONSE_FAIL
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_DATA_RESPONSE, flags)
        self.requestedFormatData = requestedFormatData
        self.formatId = formatId
        self.files = []


class ServerMonitorReadyPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241102.aspx
    """

    def __init__(self):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_MONITOR_READY, ClipboardMessageFlags.NONE)


class FormatListPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241105.aspx
    """

    def __init__(self, formatList: Dict[int, LongFormatName], msgFlags: ClipboardMessageFlags = ClipboardMessageFlags.NONE):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_LIST, msgFlags)
        self.formatList = formatList


class FormatListResponsePDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241120.aspx
    """

    def __init__(self, isSuccessful: bool = True):
        flags = ClipboardMessageFlags.CB_RESPONSE_OK if isSuccessful else ClipboardMessageFlags.CB_RESPONSE_FAIL
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_LIST_RESPONSE, flags)


class FileContentsRequestPDU(ClipboardPDU):
    def __init__(self, payload: bytes, streamId: int, lindex: int, msgFlags: int, flags: int, pos: int, size: int, clipId: int):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FILECONTENTS_REQUEST, msgFlags)
        self.payload = payload
        self.streamId = streamId
        self.lindex = lindex
        self.flags = flags
        self.offset = pos
        self.size = size
        self.clipId = clipId


class FileContentsResponsePDU(ClipboardPDU):
    def __init__(self, payload: bytes, msgFlags: int, streamId: int, data: bytes):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FILECONTENTS_RESPONSE, msgFlags)
        self.payload = payload
        self.data = data
        self.streamId = streamId
