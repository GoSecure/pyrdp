from abc import ABCMeta, abstractmethod

from pdu import MCSChannel
from router import MCSRouter
from user import MCSUser

class MCSServerConnectionObserver:
    """
    Observer class for server connections
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def connectionReceived(self, pdu):
        """
        Callback for when a Connect Initial PDU is received
        True if the connection is accepted
        """
        pass

class MCSUserIDGenerator:
    """
    User ID generator for server routers
    Generates IDs sequentially while skipping virtual channel IDs
    """
    def __init__(self, channelIDs):
        """
        :param channelIDs: list of channel IDs that can't be used for user IDs
        """
        self.next = MCSChannel.USERCHANNEL_BASE
        self.channelIDs = channelIDs
    
    def __next__(self):
        """
        Generate the next valid user ID
        """
        self.next += 1
        while self.next in self.channelIDs:
            self.next += 1
        
        return self.next

class MCSServerRouter(MCSRouter, Subject):
    """
    MCS router for server traffic
    """
    def __init__(self, factory, userIDGenerator):
        """
        :param factory: the channel factory
        :param userIDGenerator: the generator used when creating new users
        """
        super(MCSServerRouter, self).__init__()
        super(MCSServerRouter, self).__init__()
        self.factory = factory
        self.userIDGenerator = userIDGenerator
        self.users = {}

    # PDU handlers

    def connectInitial(self, pdu):
        """
        Called when a Connect Initial PDU is received
        """
        if self.observer.connectionReceived(pdu):
            self.connected = True
    
    @whenConnected
    def erectDomainRequest(self, pdu):
        """
        Called when an Erect Domain Request PDU is received
        """
        pass

    @whenConnected
    def attachUserRequest(self, pdu):
        """
        Called when an Attach User Request PDU is received
        """
        userID = next(self.userIDGenerator)
        user = MCSUser(self, self.factory)
        user.userAttached(userID)
        self.users[userID] = user

        self.findNextUser()
        self.mcs.send(MCSAttachUserConfirmPDU(0, userID))
    
    @whenConnected
    def channelJoinRequest(self, pdu):
        """
        Called when a Channel Join Request PDU is received
        """
        userID = pdu.initiator
        channelID = pdu.channelID

        if userID not in self.users:
            raise Exception("User does not exist")
        
        self.users[userID].joinedChannel(channelID)
        self.mcs.send(MCSChannelJoinConfirmPDU(0, userID, channelID, channelID, ""))
    
    @whenConnected
    def sendDataRequest(self, pdu):
        """
        Called when a Send Data Request PDU is received
        """
        userID = pdu.initiator

        if userID not in self.users:
            raise Exception("User does not exist")

        user = self.users[userID]
        user.recvSendDataRequest(pdu.channelID, pdu.payload)
        
    