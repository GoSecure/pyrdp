#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

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
    NONE = 0
    CB_RESPONSE_OK = 0x0001
    CB_RESPONSE_FAIL = 0x0002
    CB_ASCII_NAMES = 0x0004


class ClipboardFormatNumber(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc241079.aspx
    """
    GENERIC = 13
    PALETTE = 9
    METAFILE = 3


class FileDescriptorFlags(Enum):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/a765d784-2b39-4b88-9faa-88f8666f9c35
    """
    FD_ATTRIBUTES = 0x04
    FD_FILESIZE = 0x40
    FD_WRITESTIME = 0x20
    FD_SHOWPROGRESSUI = 0x4000


class FileContentsFlags(IntEnum):
    SIZE = 0x1
    RANGE = 0x2


class ClipboardFormatName(Enum):
    """
    https://msdn.microsoft.com/en-us/library/cc241079.aspx
    """
    FILE_LIST = "FileGroupDescriptorW"
    DROP_EFFECT = "Preferred DropEffect"
    FILE_CONTENT = "FileContents"
