from pyrdp.core.observer import Observer
from pyrdp.core.subject import ObservedBy, Subject
from pyrdp.mcs.router import MCSRouter
from pyrdp.mcs.user import MCSUser
from pyrdp.pdu import MCSAttachUserRequestPDU, MCSChannelJoinRequestPDU, MCSConnectResponsePDU, \
    MCSDisconnectProviderUltimatumPDU


class MCSClientConnectionObserver(Observer):
    """
    Observer class for client connections
    """
    def onConnectResponse(self, pdu):
        """
        Method called on Connect Response PDUs.
        :type pdu: MCSConnectResponsePDU
        """
    
    def onDisconnectProviderUltimatum(self, pdu):
        """
        Method called on Disconnect Provider Ultimatum PDUs.
        :type pdu: MCSDisconnectProviderUltimatumPDU
        """

class MCSClient(MCSUser):
    """
    MCSUser class with helper methods for clients
    """

    def __init__(self, router, factory):
        """
        :param router: the MCS router
        :param factory: channel factory
        """
        MCSUser.__init__(self, router, factory)
    
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

@ObservedBy(MCSClientConnectionObserver)
class MCSClientRouter(MCSRouter, Subject):
    """
    MCS router for clients.
    ObservedBy: MCSClientConnectionObserver
    """

    def __init__(self, mcs, factory):
        """
        :param factory: channel factory
        """
        MCSRouter.__init__(self, mcs)
        Subject.__init__(self)
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
        pdu = MCSChannelJoinRequestPDU(userID, channelID, b"")
        self.mcs.send(pdu)
    
    # PDU handlers

    def onConnectResponse(self, pdu):
        """
        Called when a Connect Response PDU is received
        :param pdu: the PDU
        """
        self.connected = pdu.result == 0
        self.observer.onConnectResponse(pdu)

    def onDisconnectProviderUltimatum(self, pdu):
        """
        Called when a Disconnect Provider Ultimatum PDU is received
        :param pdu: the PDU
        """
        self.observer.onDisconnectProviderUltimatum(pdu)

    def onAttachUserConfirm(self, pdu):
        """
        Called when an Attach User Confirm PDU is received
        :param pdu: the PDU
        """
        userID = pdu.initiator
        user = self.attachingUsers.pop(0)

        if userID is not None:
            self.users[userID] = user
            user.onAttachConfirmed(userID)
        else:
            user.onAttachRefused(pdu.result)
    
    def onChannelJoinConfirm(self, pdu):
        """
        Called when a Channel Join Confirm PDU is received
        :param pdu: the PDU
        """
        userID = pdu.initiator
        channelID = pdu.channelID

        if pdu.result == 0:
            self.users[userID].channelJoinAccepted(self.mcs, channelID)
        else:
            self.users[userID].channelJoinRefused(pdu.result, channelID)
    
    def onSendDataIndication(self, pdu):
        """
        Called when a Send Data Indication PDU is received
        :param pdu: the PDU
        """
        for _, user in self.users.items():
            if user.isInChannel(pdu.channelID):
                user.recvSendDataIndication(pdu.channelID, pdu)