from enum import IntEnum, Enum


class ClipboardMessageType(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc241097.aspx
    """

    CB_MONITOR_READY = 0x0001
    CB_FORMAT_LIST = 0x0002
    CB_FORMAT_LIST_RESPONSE = 0x0003
    CB_FORMAT_DATA_REQUEST = 0x0004
    CB_FORMAT_DATA_RESPONSE = 0x0005
    CB_TEMP_DIRECTORY = 0x0006
    CB_CLIP_CAPS = 0x0007
    CB_FILECONTENTS_REQUEST = 0x0008
    CB_FILECONTENTS_RESPONSE = 0x0009
    CB_LOCK_CLIPDATA = 0x000A
    CB_UNLOCK_CLIPDATA = 0x000B


class ClipboardMessageFlags(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc241097.aspx
    """

    CB_RESPONSE_OK = 0x0001
    CB_RESPONSE_FAIL = 0x0002
    CB_ASCII_NAMES = 0x0004


class ClipboardFormat(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc241079.aspx
    """
    PALETTE = 9
    METAFILE = 3


class ClipboardFormatText(Enum):
    """
    https://msdn.microsoft.com/en-us/library/cc241079.aspx
    """
    FILE_LIST = "FileGroupDescriptorW"
