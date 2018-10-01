from pdu import MCSSendDataRequestPDU, MCSSendDataIndicationPDU

class MCSChannelFactory:
    """
    Base factory class used when a user joins a new channel
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def buildChannel(self, mcs, userID, channelID):
        """
        Called when a user joins a new channel
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
    
    def recvSendDataRequest(self, data):
        """
        Called when a Send Data Request PDU is received
        """
        self.next.recvSendDataRequest(data)
    
    def recvSendDataIndication(self, data):
        """
        Called when a Send Data Indication PDU is received
        """
        self.next.recvSendDataIndication(data)
    
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