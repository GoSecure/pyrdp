from abc import ABCMeta, abstractmethod

from rdpy.core.subject import Subject

from router import MCSRouter, whenConnected
from pdu import MCSAttachUserRequestPDU, MCSChannelJoinRequestPDU, MCSSendDataRequestPDU, MCSSendDataIndicationPDU
from user import MCSUser

class MCSClientConnectionObserver:
    """
    Observer class for client connections
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def connectionSuccesful(self, pdu):
        """
        Method called on successful connections
        """
        pass
    
    @abstractmethod
    def connectionFailed(self, pdu):
        """
        Method called on failed connections
        """
        pass

class MCSClient(MCSUser):
    """
    MCSUser class with helper methods for clients
    """

    def __init__(self, router, factory):
        """
        :param router: the MCS router
        :param factory: channel factory
        """
        super(MCSClient, self).__init__(router, factory)
    
    def attach(self):
        """
        Attach this user to the MCS domain to receive a user ID
        """
        self.router.attach(self)
    
    def joinChannel(self, channelID):
        """
        Send a join channel request
        :param channelID: ID of the channel to join
        """
        self.router.joinChannel(self.userID, channelID)

class MCSClientRouter(MCSRouter, Subject):
    def __init__(self, factory):
        """
        :param factory: channel factory
        """
        super(MCSClientRouter, self).__init__()
        super(MCSClientRouter, self).__init__()
        self.factory = factory
        self.users = {}
        self.attachingUsers = []
    
    def createUser(self):
        """
        Create a new user
        """
        return MCSClient(self, self.factory)

    def attach(self, user):
        """
        Attach a user to the domain
        :param user: the user to attach
        """
        self.attachingUsers.append(user)
        pdu = MCSAttachUserRequestPDU()
        self.mcs.send(pdu)
    
    def joinChannel(self, userID, channelID):
        """
        Join a channel
        :param userID: the user ID that will join the channel
        :param channelID: the channel ID
        """
        pdu = MCSChannelJoinRequestPDU(userID, channelID, "")
        self.mcs.send(pdu)
    
    # PDU handlers

    def connectResponse(self, pdu):
        """
        Called when a Connect Response PDU is received
        :param pdu: the PDU
        """
        if pdu.result == 0:
            self.connected = True
            self.observer.connectionSuccesful(self.mcs, pdu)
        else:
            self.observer.connectionFailed(self.mcs, pdu)

    @whenConnected
    def attachUserConfirm(self, pdu):
        """
        Called when an Attach User Confirm PDU is received
        :param pdu: the PDU
        """
        userID = pdu.initiator
        user = self.attachingUsers.pop(0)
        self.users[userID] = user
        user.userAttached(self.userID)
    
    @whenConnected
    def channelJoinConfirm(self, pdu):
        """
        Called when a Channel Join Confirm PDU is received
        :param pdu: the PDU
        """
        userID = pdu.initiator
        channelID = pdu.channelID
        self.users[userID].channelJoined(channelID)
    
    @whenConnected
    def sendDataIndication(self, pdu):
        """
        Called when a Send Data Indication PDU is received
        :param pdu: the PDU
        """
        userID = pdu.initiator
        self.users[userID].recvSendDataIndication(pdu.channelID, pdu.payload)