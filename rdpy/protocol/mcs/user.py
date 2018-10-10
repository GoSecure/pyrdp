from rdpy.core.observer import Observer
from rdpy.core.subject import Subject, ObservedBy

class MCSUserObserver(Observer):
    def onAttachConfirmed(self, user):
        raise Exception("Unhandled Attach Confirmed event")
    
    def onAttachRefused(self, user):
        raise Exception("Unhandled Attach Refused event")

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
        super(MCSUser, self).__init__()
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
    
    def onAttachRefused(self):
        """
        Called when an Attach Request is refused
        """
        if self.observer:
            self.observer.onAttachRefused(self)
    
    def isInChannel(self, channelID):
        return channelID in self.channels
    
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