from rdpy.enum.mcs import MCSPDUType


class MCSPDU(object):
    """
    Base class for MCS PDUs (not actually a PDU)
    """
    def __init__(self, type, payload):
        self.header = type
        self.payload = payload


class MCSConnectInitialPDU(MCSPDU):
    def __init__(self, callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload):
        super(MCSConnectInitialPDU, self).__init__(MCSPDUType.CONNECT_INITIAL, payload)
        self.callingDomain = callingDomain
        self.calledDomain = calledDomain
        self.upward = upward
        self.targetParams = targetParams
        self.minParams = minParams
        self.maxParams = maxParams


class MCSConnectResponsePDU(MCSPDU):
    def __init__(self, result, calledConnectID, domainParams, payload):
        super(MCSConnectResponsePDU, self).__init__(MCSPDUType.CONNECT_RESPONSE, payload)
        self.result = result
        self.calledConnectID = calledConnectID
        self.domainParams = domainParams


class MCSErectDomainRequestPDU(MCSPDU):
    def __init__(self, subHeight, subInterval, payload):
        super(MCSErectDomainRequestPDU, self).__init__(MCSPDUType.ERECT_DOMAIN_REQUEST, payload)
        self.subHeight = subHeight
        self.subInterval = subInterval


class MCSDisconnectProviderUltimatumPDU(MCSPDU):
    def __init__(self, reason):
        super(MCSDisconnectProviderUltimatumPDU, self).__init__(MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM, "")
        self.reason = reason


class MCSAttachUserRequestPDU(MCSPDU):
    def __init__(self):
        super(MCSAttachUserRequestPDU, self).__init__(MCSPDUType.ATTACH_USER_REQUEST, "")


class MCSAttachUserConfirmPDU(MCSPDU):
    def __init__(self, result, initiator = None):
        super(MCSAttachUserConfirmPDU, self).__init__(MCSPDUType.ATTACH_USER_CONFIRM, "")
        self.result = result
        self.initiator = initiator


class MCSChannelJoinRequestPDU(MCSPDU):
    def __init__(self, initiator, channelID, payload):
        super(MCSChannelJoinRequestPDU, self).__init__(MCSPDUType.CHANNEL_JOIN_REQUEST, payload)
        self.initiator = initiator
        self.channelID = channelID


class MCSChannelJoinConfirmPDU(MCSPDU):
    def __init__(self, result, initiator, requested, channelID, payload):
        super(MCSChannelJoinConfirmPDU, self).__init__(MCSPDUType.CHANNEL_JOIN_CONFIRM, payload)
        self.result = result
        self.initiator = initiator
        self.requested = requested
        self.channelID = channelID


class MCSSendDataRequestPDU(MCSPDU):
    def __init__(self, initiator, channelID, priority, payload):
        super(MCSSendDataRequestPDU, self).__init__(MCSPDUType.SEND_DATA_REQUEST, payload)
        self.initiator = initiator
        self.channelID = channelID
        self.priority = priority


class MCSSendDataIndicationPDU(MCSPDU):
    def __init__(self, initiator, channelID, priority, payload):
        super(MCSSendDataIndicationPDU, self).__init__(MCSPDUType.SEND_DATA_INDICATION, payload)
        self.initiator = initiator
        self.channelID = channelID
        self.priority = priority


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