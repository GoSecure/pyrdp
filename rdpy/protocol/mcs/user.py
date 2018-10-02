from abc import ABCMeta, abstractmethod

from rdpy.core.subject import Subject

class MCSUserObserver:
    __metaclass__ = ABCMeta

    @abstractmethod
    def attachConfirmed(self, user):
        pass
    
    @abstractmethod
    def attachRefused(self, user):
        pass

class MCSUser(Subject):
    def __init__(self, router, factory):
        """
        :param router: the MCS router
        :param factory: the channel factory
        """
        super(MCSUser, self).__init__()
        self.userID = None
        self.factory = factory
        self.channels = {}
        self.router = router
    
    def attachConfirmed(self, userID):
        """
        Called when a user was attached
        :param userID: the user ID assigned to this user
        """
        self.userID = userID

        if self.observer:
            self.observer.attachConfirmed(self)
    
    def attachRefused(self):
        """
        Called when an Attach Request is refused
        """
        if self.observer:
            self.observer.attachRefused(self)
    
    def channelJoined(self, mcs, channelID):
        """
        Called when a channel was joined
        :param mcs: the MCS layer
        :param channelID: ID of the channel to join
        """
        channel = self.factory.buildChannel(mcs, self.userID, channelID)
        self.channels[channelID] = channel
    
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