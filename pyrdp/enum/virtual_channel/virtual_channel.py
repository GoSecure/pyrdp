#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum


class VirtualChannelPDUFlag(IntEnum):
    """
    https://msdn.microsoft.com/en-us/library/cc240553.aspx
    """

    CHANNEL_FLAG_FIRST = 0x00000001
    CHANNEL_FLAG_LAST = 0x00000002
    CHANNEL_FLAG_SHOW_PROTOCOL = 0x00000010
    CHANNEL_FLAG_SUSPEND = 0x00000020
    CHANNEL_FLAG_RESUME = 0x00000040
    CHANNEL_PACKET_COMPRESSED = 0x00200000
    CHANNEL_PACKET_AT_FRONT = 0x00400000
    CHANNEL_PACKET_FLUSHED = 0x00800000
    CompressionTypeMask = 0x000F0000


