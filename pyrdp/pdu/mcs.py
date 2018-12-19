#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import pprint

from pyrdp.enum import MCSPDUType
from pyrdp.pdu.pdu import PDU


class MCSPDU(PDU):
    """
    Base class for MCS (T.125) PDUs (not actually a PDU). Every MCS PDU has a PDU type (header) and a payload.
    """
    def __init__(self, pduType, payload):
        """
        :type pduType: MCSPDUType
        :type payload: bytes
        """

        PDU.__init__(self, payload)
        self.header = pduType


class MCSConnectInitialPDU(MCSPDU):
    def __init__(self, callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload):
        MCSPDU.__init__(self, MCSPDUType.CONNECT_INITIAL, payload)
        self.callingDomain = callingDomain
        self.calledDomain = calledDomain
        self.upward = upward
        self.targetParams = targetParams
        self.minParams = minParams
        self.maxParams = maxParams


class MCSConnectResponsePDU(MCSPDU):
    def __init__(self, result, calledConnectID, domainParams, payload):
        MCSPDU.__init__(self, MCSPDUType.CONNECT_RESPONSE, payload)
        self.result = result
        self.calledConnectID = calledConnectID
        self.domainParams = domainParams


class MCSErectDomainRequestPDU(MCSPDU):
    def __init__(self, subHeight, subInterval, payload):
        MCSPDU.__init__(self, MCSPDUType.ERECT_DOMAIN_REQUEST, payload)
        self.subHeight = subHeight
        self.subInterval = subInterval


class MCSDisconnectProviderUltimatumPDU(MCSPDU):
    def __init__(self, reason):
        MCSPDU.__init__(self, MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM, b"")
        self.reason = reason


class MCSAttachUserRequestPDU(MCSPDU):
    def __init__(self):
        MCSPDU.__init__(self, MCSPDUType.ATTACH_USER_REQUEST, b"")


class MCSAttachUserConfirmPDU(MCSPDU):
    def __init__(self, result, initiator = None):
        MCSPDU.__init__(self, MCSPDUType.ATTACH_USER_CONFIRM, b"")
        self.result = result
        self.initiator = initiator


class MCSChannelJoinRequestPDU(MCSPDU):
    def __init__(self, initiator, channelID, payload):
        MCSPDU.__init__(self, MCSPDUType.CHANNEL_JOIN_REQUEST, payload)
        self.initiator = initiator
        self.channelID = channelID


class MCSChannelJoinConfirmPDU(MCSPDU):
    def __init__(self, result, initiator, requested, channelID, payload):
        MCSPDU.__init__(self, MCSPDUType.CHANNEL_JOIN_CONFIRM, payload)
        self.result = result
        self.initiator = initiator
        self.requested = requested
        self.channelID = channelID


class MCSSendDataRequestPDU(MCSPDU):
    def __init__(self, initiator, channelID, priority, payload):
        MCSPDU.__init__(self, MCSPDUType.SEND_DATA_REQUEST, payload)
        self.initiator = initiator
        self.channelID = channelID
        self.priority = priority


class MCSSendDataIndicationPDU(MCSPDU):
    def __init__(self, initiator, channelID, priority, payload):
        MCSPDU.__init__(self, MCSPDUType.SEND_DATA_INDICATION, payload)
        self.initiator = initiator
        self.channelID = channelID
        self.priority = priority


class MCSDomainParams(PDU):
    def __init__(self, maxChannelIDs, maxUserIDs, maxTokenIDs, numPriorities, minThroughput, maxHeight, maxMCSPDUSize,
                 protocolVersion):
        super().__init__()
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

    def __repr__(self):
        return pprint.pformat(vars(self))