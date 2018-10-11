class MCSPDUType:
    """
    MCS PDU Headers
    """
    # Connection PDU headers
    CONNECT_INITIAL = 0x65
    CONNECT_RESPONSE = 0x66

    # Domain PDU headers
    ERECT_DOMAIN_REQUEST = 1
    DISCONNECT_PROVIDER_ULTIMATUM = 8
    ATTACH_USER_REQUEST = 10
    ATTACH_USER_CONFIRM = 11
    CHANNEL_JOIN_REQUEST = 14
    CHANNEL_JOIN_CONFIRM = 15
    SEND_DATA_REQUEST = 25
    SEND_DATA_INDICATION = 26

class MCSChannel:
    """
    Channel IDs of the main channels used in RDP
    """
    USERCHANNEL_BASE = 1001
    GLOBAL_CHANNEL = 1003
    RDPDR_CHANNEL = 1004  # Not handled by RDPY
    CLIPRDR_CHANNEL = 1005  # Not handled by RDPY
    RDPSND_CHANNEL = 1006  # Not handled by RDPY

class MCSResult:
    RT_SUCCESSFUL = 0x00

class MCSDomainParams:
    def __init__(self, maxChannelIDs, maxUserIDs, maxTokenIDs, numPriorities, minThroughput, maxHeight, maxMCSPDUSize, protocolVersion):
        self.maxChannelIDs = maxChannelIDs
        self.maxUserIDs = maxUserIDs
        self.maxTokenIDs = maxTokenIDs
        self.numPriorities = numPriorities
        self.minThroughput = minThroughput
        self.maxHeight = maxHeight
        self.maxMCSPDUSize = maxMCSPDUSize
        self.protocolVersion = protocolVersion
    
    @staticmethod
    def createTarget(maxChannelIDs, maxUserIDs):
        return MCSDomainParams(maxChannelIDs, maxUserIDs, 0, 1, 0, 1, 65535, 2)

    @staticmethod
    def createMinimum():
        return MCSDomainParams(1, 1, 1, 1, 0, 1, 1056, 2)

    @staticmethod
    def createMaximum():
        return MCSDomainParams(65535, 64535, 65535, 1, 0, 1, 65535, 2)


