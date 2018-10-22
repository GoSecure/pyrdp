from abc import ABCMeta, abstractmethod

from rdpy.core.newlayer import Layer
from rdpy.pdu.mcs import MCSSendDataRequestPDU, MCSSendDataIndicationPDU


class MCSChannelFactory:
    """
    Base factory class used when a user joins a new channel
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def buildChannel(self, mcs, userID, channelID):
        """
        Called when a user joins a new channel
        :param mcs: the MCS layer
        :param userID: the user ID
        :param channelID: the channel ID
        :return: An MCSChannel object
        """
        pass


class MCSChannel:
    """
    Base class for MCS channels
    A new MCS channel is actually created for every (userID, channelID) pair
    """
    
    def __init__(self, mcs, userID, channelID):
        """
        :param mcs: the MCS layer
        :param userID: the user ID for this channel
        :param channelID: the channel ID for this channel
        """
        self.mcs = mcs
        self.userID = userID
        self.channelID = channelID
    
    def recvSendDataRequest(self, pdu):
        """
        Called when a Send Data Request PDU is received
        """
        raise NotImplementedError("Unhandled Send Data Request PDU")
    
    def recvSendDataIndication(self, pdu):
        """
        Called when a Send Data Indication PDU is received
        """
        raise NotImplementedError("Unhandled Send Data Indication PDU")
    
    def sendSendDataRequest(self, data):
        """
        Send a Send Data Request PDU from this channel
        :param data: the PDU's payload
        """
        pdu = MCSSendDataRequestPDU(self.userID, self.channelID, 0x70, data)
        self.mcs.send(pdu)
    
    def sendSendDataIndication(self, data):
        """
        Send a Send Data Indication PDU from this channel
        :param data: the PDU's payload
        """
        pdu = MCSSendDataIndicationPDU(self.userID, self.channelID, 0x70, data)
        self.mcs.send(pdu)


class MCSClientChannel(MCSChannel, Layer):
    def __init__(self, mcs, userID, channelID):
        MCSChannel.__init__(self, mcs, userID, channelID)
        Layer.__init__(self)
    
    def recvSendDataIndication(self, pdu):
        self.next.recv(pdu.payload)
    
    def send(self, data):
        self.sendSendDataRequest(data)


class MCSServerChannel(MCSChannel, Layer):
    def __init__(self, mcs, userID, channelID):
        MCSChannel.__init__(self, mcs, userID, channelID)
        Layer.__init__(self)
        pass
    
    def recvSendDataRequest(self, pdu):
        self.next.recv(pdu)
    
    def send(self, data):
        self.sendSendDataIndication(data)
