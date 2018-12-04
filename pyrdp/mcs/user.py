from pyrdp.core.observer import Observer
from pyrdp.core.subject import Subject, ObservedBy

class MCSUserObserver(Observer):
    """
    Base observer class for MCS users.
    """

    def onAttachConfirmed(self, user):
        pass

    def onAttachRefused(self, user, result):
        pass

    def onChannelJoinRefused(self, user, result, channelID):
        pass

@ObservedBy(MCSUserObserver)
class MCSUser(Subject):
    """
    MCS User class.
    ObservedBy: MCSUserObserver
    """

    def __init__(self, router, factory):
        """
        :param router: the MCS router
        :param factory: the channel factory
        """
        Subject.__init__(self)
        self.userID = None
        self.factory = factory
        self.channels = {}
        self.router = router
    
    def onAttachConfirmed(self, userID):
        """
        Called when a user was attached
        :param userID: the user ID assigned to this user
        """
        self.userID = userID

        if self.observer:
            self.observer.onAttachConfirmed(self)
    
    def onAttachRefused(self, result):
        """
        Called when an Attach Request is refused
        """
        if self.observer:
            self.observer.onAttachRefused(self, result)
    
    def isInChannel(self, channelID):
        """
        Check if the user is in a channel.
        :param channelID: the channel ID.
        :type channelID: int
        """
        return channelID in self.channels
    
    def channelJoinAccepted(self, mcs, channelID):
        """
        Called when a channel was joined
        :param mcs: the MCS layer
        :param channelID: ID of the channel to join
        """
        channel = self.factory.buildChannel(mcs, self.userID, channelID)
        self.channels[channelID] = channel

    def channelJoinRefused(self, result, channelID):
        """
        Called when a channel could not be joined.
        :param result: result code.
        :param channelID: ID of the channel.
        """
        self.observer.onChannelJoinRefused(self, result, channelID)
    
    def recvSendDataRequest(self, channelID, data):
        """
        Receive a Send Data Request PDU
        :param channelID: ID of the channel on which the data was sent
        :param data: the PDU's payload
        """
        self.channels[channelID].recvSendDataRequest(data)
    
    def recvSendDataIndication(self, channelID, data):
        """
        Receive a Send Data Indication PDU
        :param channelID: ID of the channel on which the data was sent
        :param data: the PDU's payload
        """
        self.channels[channelID].recvSendDataIndication(data)