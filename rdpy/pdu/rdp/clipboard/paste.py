"""
Paste sequence: https://msdn.microsoft.com/en-us/library/cc241121.aspx
"""
from rdpy.enum.clipboard.clipboard import ClipboardMessageType, ClipboardMessageFlags
from rdpy.pdu.rdp.clipboard.clipboard import ClipboardPDU


class FormatDataRequestPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241122.aspx
    """

    def __init__(self, requestedFormatId):
        """
        :type requestedFormatId: rdpy.enum.clipboard.clipboard.ClipboardFormat
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
