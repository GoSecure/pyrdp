"""
Copy sequence: https://msdn.microsoft.com/en-us/library/cc241104.aspx
"""
from rdpy.enum.clipboard.clipboard import ClipboardMessageFlags, ClipboardMessageType
from rdpy.pdu.rdp.clipboard.clipboard import ClipboardPDU


class FormatListPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241105.aspx
    """

    def __init__(self, formatListData, msgFlags=0x0000):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_LIST, msgFlags)
        self.formatListData = formatListData


class FormatListResponsePDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241120.aspx
    """

    def __init__(self, isSuccessful=True):
        flags = ClipboardMessageFlags.CB_RESPONSE_OK if isSuccessful else ClipboardMessageFlags.CB_RESPONSE_FAIL
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_FORMAT_LIST_RESPONSE, flags)
