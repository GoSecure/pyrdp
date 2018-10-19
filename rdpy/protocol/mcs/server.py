from rdpy.core.observer import Observer
from rdpy.core.subject import Subject, ObservedBy
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
        self.observer.onAttachUserRequest(pdu)

    @whenConnected
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
    
    @whenConnected
    def onChannelJoinRequest(self, pdu):
        """
        Called when a Channel Join Request PDU is received
        """
        self.observer.onChannelJoinRequest(pdu)

    @whenConnected
    def sendChannelJoinConfirm(self, result, userID, channelID):
        """
        Send a Channel Join Confirm PDU.
        :param result: the result code (0 if the request was successful).
        :type result: int
        :param userID: the user ID.
        :type result: int
        :param channelID: the channel ID.
        :type channelID: int
        """
        if result == 0:
            self.users[userID].channelJoinAccepted(self.mcs, channelID)
        else:
            self.users[userID].channelJoinRefused(result, channelID)

        pdu = MCSChannelJoinConfirmPDU(result, userID, channelID, channelID, "")
        self.mcs.send(pdu)

    @whenConnected
    def onSendDataRequest(self, pdu):
        """
        Called when a Send Data Request PDU is received.
        """
        userID = pdu.initiator

        if userID not in self.users:
            raise Exception("User does not exist")

        user = self.users[userID]
        user.recvSendDataRequest(pdu.channelID, pdu.payload)
        
    