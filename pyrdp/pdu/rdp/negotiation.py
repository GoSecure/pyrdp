#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional

from pyrdp.enum import NegotiationFailureCode, NegotiationProtocols, NegotiationRequestFlags, NegotiationType
from pyrdp.pdu.pdu import PDU


class NegotiationRequestPDU(PDU):
    """
    First PDU of the RDP connection sequence. Sent by the client.
    """
    def __init__(self, cookie: Optional[bytes], flags: Optional[NegotiationRequestFlags], requestedProtocols: Optional[NegotiationProtocols], correlationFlags: Optional[int] = None, correlationID: Optional[int] = None):
        """
        :param cookie: mstshash identifier or routing token.
        :param flags: request flags.
        :param requestedProtocols: transport protocols supported by the client.
        :param correlationFlags: correlation info flags.
        :param correlationID: correlation info id.
        """
        PDU.__init__(self)
        self.cookie = cookie
        self.flags = flags
        self.packetType = NegotiationType.TYPE_RDP_NEG_REQ
        self.requestedProtocols = requestedProtocols
        self.tlsSupported = requestedProtocols is not None and requestedProtocols & NegotiationProtocols.SSL != 0
        self.credSspSupported = requestedProtocols is not None and requestedProtocols & NegotiationProtocols.CRED_SSP != 0
        self.earlyUserAuthSupported = requestedProtocols is not None and requestedProtocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0
        self.correlationFlags = correlationFlags
        self.correlationID = correlationID


class NegotiationResponsePDU(PDU):
    """
    Second PDU of the RDP connection sequence. Sent by the server.
    Important information is the chosen encryption method.
    """
    def __init__(self, type: Optional[int], flags: Optional[int], selectedProtocols: Optional[NegotiationProtocols]):
        """
        :param flags: response flags.
        :param selectedProtocols: transport protocol chosen by the server.
        """
        PDU.__init__(self)
        self.type = type
        self.packetType = NegotiationType.TYPE_RDP_NEG_RSP
        self.length = 8
        self.flags = flags
        self.selectedProtocols = selectedProtocols
        self.tlsSelected = selectedProtocols is not None and selectedProtocols & NegotiationProtocols.SSL != 0
        self.credSspSelected = selectedProtocols is not None and selectedProtocols & NegotiationProtocols.CRED_SSP != 0
        self.earlyUserAuthSelected = selectedProtocols is not None and selectedProtocols & NegotiationProtocols.EARLY_USER_AUTHORIZATION_RESULT != 0

class NegotiationFailurePDU(PDU):
    """
    Special PDU indicating failure. Sent by the server.
    """
    def __init__(self, type: Optional[int], flags: Optional[int], failureCode: NegotiationFailureCode):
        """
        :param flags: response flags.
        :param failureCode: error from the server
        """
        PDU.__init__(self)
        self.type = type
        self.packetType = NegotiationType.TYPE_RDP_NEG_RSP
        self.length = 8
        self.flags = flags
        self.failureCode = failureCode
