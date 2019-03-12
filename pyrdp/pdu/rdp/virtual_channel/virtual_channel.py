#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.enum import VirtualChannelPDUFlag
from pyrdp.pdu.pdu import PDU


class VirtualChannelPDU(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc240553.aspx
    """

    def __init__(self, flags: VirtualChannelPDUFlag, payload: bytes):
        """
        :param flags: PDU flags (CHANNEL_FLAG_FIRST and CHANNEL_FLAG_LAST are added automatically when writing).
        :param payload: the payload.
        """
        PDU.__init__(self, payload)
        self.flags = flags
