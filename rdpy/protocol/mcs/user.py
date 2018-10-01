class MCSUser:
    def __init__(self, router, factory):
        """
        :param router: the MCS router
        :param factory: the channel factory
        """
        self.userID = None
        self.factory = factory
        self.channels = {}
        self.router = router
    
    def userAttached(self, userID):
        """
        Called when a user was attached
        :param userID: the user ID assigned to this user
        """
        self.userID = userID
    
    def channelJoined(self, channelID):
        """
        Called when a channel was joined
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