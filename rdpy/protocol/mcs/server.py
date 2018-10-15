from rdpy.core.observer import Observer
from rdpy.core.subject import Subject, ObservedBy
from rdpy.enum.mcs import MCSChannelID
from rdpy.pdu.mcs import MCSAttachUserConfirmPDU, MCSChannelJoinConfirmPDU
from router import MCSRouter, whenConnected
from user import MCSUser


class MCSServerConnectionObserver(Observer):
    """
    Observer class for server connections
    """
    def __init__(self, **kwargs):
        Observer.__init__(self, **kwargs)

    def onConnectionReceived(self, pdu):
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
        self.next_channel = MCSChannelID.USERCHANNEL_BASE
        self.channelIDs = channelIDs
    
    def next(self):
        """
        Generate the next valid user ID
        """
        self.next_channel += 1
        while self.next_channel in self.channelIDs:
            self.next_channel += 1
        
        return self.next_channel

@ObservedBy(MCSServerConnectionObserver)
class MCSServerRouter(MCSRouter, Subject):
    """
    MCS router for server traffic
    """
    def __init__(self, mcs, factory, userIDGenerator):
        """
        :param mcs: MCSLayer
        :param factory: the channel factory
        :param userIDGenerator: the generator used when creating new users
        :type userIDGenerator: MCSUserIDGenerator
        """
        MCSRouter.__init__(self, mcs)
        Subject.__init__(self)
        self.factory = factory
        self.userIDGenerator = userIDGenerator
        self.users = {}

    # PDU handlers

    def onConnectInitial(self, pdu):
        """
        Called when a Connect Initial PDU is received
        """
        if self.observer.onConnectionReceived(pdu):
            self.connected = True
    
    @whenConnected
    def onErectDomainRequest(self, pdu):
        """
        Called when an Erect Domain Request PDU is received
        """
        pass

    @whenConnected
    def onAttachUserRequest(self, pdu):
        """
        Called when an Attach User Request PDU is received
        """
        userID = next(self.userIDGenerator)
        user = MCSUser(self, self.factory)
        user.onAttachConfirmed(userID)
        self.users[userID] = user

        self.mcs.send(MCSAttachUserConfirmPDU(0, userID))
    
    @whenConnected
    def onChannelJoinRequest(self, pdu):
        """
        Called when a Channel Join Request PDU is received
        """
        userID = pdu.initiator
        channelID = pdu.channelID

        if userID not in self.users:
            raise Exception("User does not exist")
        
        self.users[userID].channelJoined(self.mcs, channelID)
        self.mcs.send(MCSChannelJoinConfirmPDU(0, userID, channelID, channelID, ""))
    
    @whenConnected
    def onSendDataRequest(self, pdu):
        """
        Called when a Send Data Request PDU is received
        """
        userID = pdu.initiator

        if userID not in self.users:
            raise Exception("User does not exist")

        user = self.users[userID]
        user.recvSendDataRequest(pdu.channelID, pdu.payload)
        
    