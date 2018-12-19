#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.pdu.pdu import PDU


class VirtualChannelPDU(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc240553.aspx
    """

    def __init__(self, length, flags, payload):
        PDU.__init__(self, payload)
        self.length = length
        self.flags = flags
