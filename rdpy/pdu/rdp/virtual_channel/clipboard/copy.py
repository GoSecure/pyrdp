"""
Copy sequence: https://msdn.microsoft.com/en-us/library/cc241104.aspx
"""
from rdpy.enum.virtual_channel.clipboard.clipboard import ClipboardMessageFlags, ClipboardMessageType
from rdpy.pdu.rdp.virtual_channel.clipboard.clipboard import ClipboardPDU


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


class FormatName:
    def __init__(self, formatId, formatName):
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
