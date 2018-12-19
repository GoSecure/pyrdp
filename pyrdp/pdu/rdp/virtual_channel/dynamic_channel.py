#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum.virtual_channel.dynamic_channel import CbId, DynamicChannelCommand
from pyrdp.pdu import PDU


class DynamicChannelPDU(PDU):
    """
    Base for DynamicChannelPDUs
    https://msdn.microsoft.com/en-us/library/cc241267.aspx
    """

    def __init__(self, cbid: int, sp: int, cmd: int, payload=b""):
        super().__init__(payload)
        self.cbid = CbId(cbid)
        self.sp = sp
        self.cmd = DynamicChannelCommand(cmd)


class CreateRequestPDU(DynamicChannelPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241244.aspx
    """

    def __init__(self, cbid: int, sp: int, channelId: int, channelName: str):
        super().__init__(cbid, sp, DynamicChannelCommand.CREATE)
        self.channelId = channelId
        self.channelName = channelName


class CreateResponsePDU(DynamicChannelPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241245.aspx
    """

    def __init__(self, cbid, sp, channelId: int, creationStatus: int):
        super().__init__(cbid, sp, DynamicChannelCommand.CREATE)
        self.channelId = channelId
        self.creationStatus = creationStatus
