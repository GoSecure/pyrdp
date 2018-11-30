from rdpy.enum.virtual_channel.clipboard import ClipboardMessageType, ClipboardMessageFlags
from rdpy.pdu.base_pdu import PDU


class ClipboardPDU(PDU):
    """
    Not a PDU, just a base class for every other clipboard PDUs.
    https://msdn.microsoft.com/en-us/library/cc241097.aspx
    """

    def __init__(self, msgType, msgFlags, payload=None):
        PDU.__init__(self, payload)
        self.msgType = msgType
        self.msgFlags = msgFlags


class FormatDataRequestPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241122.aspx
    """

    def __init__(self, requestedFormatId):
        """
        :type requestedFormatId: rdpy.enum.clipboard.ClipboardFormat
        """
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_DATA_REQUEST, 0x0000)
        self.requestedFormatId = requestedFormatId


class FormatDataResponsePDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241123.aspx
    """

    def __init__(self, requestedFormatData, isSuccessful=True):
        flags = ClipboardMessageFlags.CB_RESPONSE_OK if isSuccessful else ClipboardMessageFlags.CB_RESPONSE_FAIL
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_DATA_RESPONSE, flags)
        self.requestedFormatData = requestedFormatData


class ServerMonitorReadyPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241102.aspx
    """

    def __init__(self):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_MONITOR_READY, 0x0000)


class FormatListPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241105.aspx
    """

    def __init__(self, formatList, msgFlags=0x0000):
        """
        :type formatList: dict[LongFormatName]
        :type msgFlags: int
        """
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_LIST, msgFlags)
        self.formatList = formatList


class FormatListResponsePDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241120.aspx
    """

    def __init__(self, isSuccessful=True):
        flags = ClipboardMessageFlags.CB_RESPONSE_OK if isSuccessful else ClipboardMessageFlags.CB_RESPONSE_FAIL
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_LIST_RESPONSE, flags)


class FormatName(PDU):
    def __init__(self, formatId, formatName):
        super().__init__()
        self.formatId = formatId
        self.formatName = formatName


class ShortFormatName(FormatName):
    """
    https://msdn.microsoft.com/en-us/library/cc241107.aspx
    """


class LongFormatName(FormatName):
    """
    https://msdn.microsoft.com/en-us/library/cc241109.aspx
    """
    pass
