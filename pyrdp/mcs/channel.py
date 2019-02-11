#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from abc import ABCMeta, abstractmethod

from pyrdp.layer import MCSLayer
from pyrdp.layer.layer import LayerChainItem
from pyrdp.pdu import MCSSendDataIndicationPDU, MCSSendDataRequestPDU


class MCSChannel(LayerChainItem, metaclass=ABCMeta):
    """
    Base class for MCS channels
    A new MCS channel is actually created for every (userID, channelID) pair
    """

    def __init__(self, mcs: MCSLayer, userID: int, channelID: int):
        """
        :param mcs: the MCS layer
        :param userID: the user ID for this channel
        :param channelID: the channel ID for this channel
        """
        super().__init__()
        self.mcs = mcs
        self.userID = userID
        self.channelID = channelID

    def recv(self, data: bytes):
        if self.next is not None:
            self.next.recv(data)


class MCSClientChannel(MCSChannel):
    """
    MCSChannel class and layer for clients.
    Sends SendDataRequest PDUs when sendBytes is called.
    """

    def sendBytes(self, data: bytes):
        pdu = MCSSendDataRequestPDU(self.userID, self.channelID, 0x70, data)
        self.mcs.sendPDU(pdu)


class MCSServerChannel(MCSChannel):
    """
    MCSChannel class and layer for servers.
    Sends SendDataIndication PDUs when sendBytes is called.
    """

    def sendBytes(self, data: bytes):
        pdu = MCSSendDataIndicationPDU(self.userID, self.channelID, 0x70, data)
        self.mcs.sendPDU(pdu)


class MCSChannelFactory(metaclass = ABCMeta):
    """
    Base factory class used when a user joins a new channel
    """

    @abstractmethod
    def buildChannel(self, mcs: 'MCSLayer', userID: int, channelID: int) -> MCSChannel:
        """
        Called when a user joins a new channel
        :param mcs: the MCS layer
        :param userID: the user ID
        :param channelID: the channel ID
        """
        pass
