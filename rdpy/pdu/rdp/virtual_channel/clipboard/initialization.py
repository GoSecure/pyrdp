"""
Initialization sequence: https://msdn.microsoft.com/en-us/library/cc241098.aspx
"""
from rdpy.enum.virtual_channel.clipboard.clipboard import ClipboardMessageType
from rdpy.pdu.rdp.virtual_channel.clipboard import ClipboardPDU


class ServerMonitorReadyPDU(ClipboardPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241102.aspx
    """

    def __init__(self):
        ClipboardPDU.__init__(self, ClipboardMessageType.CB_MONITOR_READY, 0x0000)