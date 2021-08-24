#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2020 GoSecure Inc.
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


class DataPDU(DynamicChannelPDU):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/15b59886-db44-47f1-8da3-47c8fcd82803
    """

    def __init__(self, cbid, sp, channelId: int, payload: bytes):
        super().__init__(cbid, sp, DynamicChannelCommand.DATA, payload=payload)
        self.channelId = channelId
