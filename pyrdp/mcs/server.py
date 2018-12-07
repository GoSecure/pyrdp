from pyrdp.core import ObservedBy, Observer, Subject
from pyrdp.mcs.router import MCSRouter
from pyrdp.mcs.user import MCSUser
from pyrdp.pdu import MCSAttachUserConfirmPDU, MCSChannelJoinConfirmPDU, MCSSendDataRequestPDU


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

    def onDisconnectProviderUltimatum(self, pdu):
        """
        Method called on Disconnect Provider Ultimatum PDUs.
        """
        pass

    def onAttachUserRequest(self, pdu):
        """
        Callback for when an Attach User Request PDU is received. The observer should eventually call
        sendAttachUserConfirm to send the confirmation message to the client.
        """
        pass

    def onChannelJoinRequest(self, pdu):
        """
        Callback for when an Channel Join Request PDU is received. The observer should eventually call
        sendChannelJoinConfirm to send the confirmation message to the client.
        """
        pass

@ObservedBy(MCSServerConnectionObserver)
class MCSServerRouter(MCSRouter, Subject):
    """
    MCS router for server traffic
    """
    def __init__(self, mcs, factory):
        """
        :param mcs: the MCS layer.
        :type mcs: MCSLayer
        :param factory: the channel factory.
        :type factory: MCSChannelFactory
        """
        MCSRouter.__init__(self, mcs)
        Subject.__init__(self)
        self.factory = factory
        self.users = {}

    # PDU handlers

    def onConnectInitial(self, pdu):
        """
        Called when a Connect Initial PDU is received
        """
        if self.observer.onConnectionReceived(pdu):
            self.connected = True

    def onDisconnectProviderUltimatum(self, pdu):
        """
        Called when a Disconnect Provider Ultimatum PDU is received
        """
        self.observer.onDisconnectProviderUltimatum(pdu)

    def onErectDomainRequest(self, pdu):
        """
        Called when an Erect Domain Request PDU is received
        """
        pass

    def onAttachUserRequest(self, pdu):
        """
        Called when an Attach User Request PDU is received
        """
        self.observer.onAttachUserRequest(pdu)

    def sendAttachUserConfirm(self, success, param):
        """
        Send an Attach User Confirm PDU to the client.
        :param success: whether the request was successful or not.
        :type success: bool
        :param param: if the request was successful, then this is a user ID. Otherwise, this is the error code.
        :type param: int
        """
        if success:
            userID = param
            user = MCSUser(self, self.factory)
            self.users[userID] = user
            user.onAttachConfirmed(userID)
            pdu = MCSAttachUserConfirmPDU(0, userID)
        else:
            pdu = MCSAttachUserConfirmPDU(param, None)

        self.mcs.send(pdu)
    
    def onChannelJoinRequest(self, pdu):
        """
        Called when a Channel Join Request PDU is received
        """
        self.observer.onChannelJoinRequest(pdu)

    def sendChannelJoinConfirm(self, result, userID, channelID, notify = True):
        """
        Send a Channel Join Confirm PDU.
        :param result: the result code (0 if the request was successful).
        :type result: int
        :param userID: the user ID.
        :type result: int
        :param channelID: the channel ID.
        :type channelID: int
        :param notify: True if the user should be notified (default).
        :type notify: bool
        """

        if notify:
            if result == 0:
                self.users[userID].channelJoinAccepted(self.mcs, channelID)
            else:
                self.users[userID].channelJoinRefused(result, channelID)

        pdu = MCSChannelJoinConfirmPDU(result, userID, channelID, channelID, b"")
        self.mcs.send(pdu)

    def onSendDataRequest(self, pdu: MCSSendDataRequestPDU):
        """
        Called when a Send Data Request PDU is received.
        """
        userID = pdu.initiator

        if userID not in self.users:
            self.onInvalidMCSUser(userID)

        user = self.users[userID]
        user.recvSendDataRequest(pdu.channelID, pdu)
        
    def onInvalidMCSUser(self, userID: int):
        raise ValueError(f"User does not exist: {userID}")


