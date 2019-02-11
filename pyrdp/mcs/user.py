#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict

from pyrdp.enum.mcs import MCSResult

from pyrdp.core import ObservedBy, Observer, Subject
from pyrdp.layer import MCSLayer
from pyrdp.mcs import MCSChannelFactory, MCSChannel
from pyrdp.pdu import MCSSendDataRequestPDU


class MCSUserObserver(Observer):
    """
    Base observer class for MCS users.
    """

    def onAttachConfirmed(self, user: 'MCSUser'):
        pass

    def onAttachRefused(self, user: 'MCSUser', result: MCSResult):
        pass

    def onChannelJoinRefused(self, user: 'MCSUser', result: MCSResult, channelID: int):
        pass


@ObservedBy(MCSUserObserver)
class MCSUser(Subject):
    """
    MCS User class.
    ObservedBy: MCSUserObserver
    """

    def __init__(self, router: 'MCSRouter', factory: MCSChannelFactory):
        """
        :param router: the MCS router
        :param factory: the channel factory
        """
        Subject.__init__(self)
        self.router = router
        self.factory = factory
        self.userID: int = None
        self.channels: Dict[int, MCSChannel] = {}

    def onAttachConfirmed(self, userID: int):
        """
        Called when a user was attached
        :param userID: the user ID assigned to this user
        """
        self.userID = userID

        if self.observer:
            self.observer.onAttachConfirmed(self)
    
    def onAttachRefused(self, result: MCSResult):
        """
        Called when an Attach Request is refused
        """
        if self.observer:
            self.observer.onAttachRefused(self, result)
    
    def isInChannel(self, channelID: int):
        """
        Check if the user is in a channel.
        :param channelID: the channel ID.
        :type channelID: int
        """
        return channelID in self.channels
    
    def channelJoinAccepted(self, mcs: MCSLayer, channelID: int):
        """
        Called when a channel was joined
        :param mcs: the MCS layer
        :param channelID: ID of the channel to join
        """
        channel = self.factory.buildChannel(mcs, self.userID, channelID)
        self.channels[channelID] = channel

    def channelJoinRefused(self, result: MCSResult, channelID: int):
        """
        Called when a channel could not be joined.
        :param result: result code.
        :param channelID: ID of the channel.
        """
        self.observer.onChannelJoinRefused(self, result, channelID)
    
    def recvSendDataRequest(self, channelID: int, pdu: MCSSendDataRequestPDU):
        """
        Receive a Send Data Request PDU
        :param channelID: ID of the channel on which the data was sent
        :param pdu: the PDU's payload
        """
        self.channels[channelID].recv(pdu.payload)
    
    def recvSendDataIndication(self, channelID: int, pdu: MCSSendDataRequestPDU):
        """
        Receive a Send Data Indication PDU
        :param channelID: ID of the channel on which the data was sent
        :param pdu: the PDU's payload
        """
        self.channels[channelID].recv(pdu.payload)